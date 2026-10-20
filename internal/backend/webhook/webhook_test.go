package webhook_test

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/webhook"
)

const zone = "example.test."

// endpoint records the requests it receives, and answers with its handler.
type endpoint struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []received
}

type received struct {
	header http.Header
	body   []byte
}

func newEndpoint(t *testing.T, tls bool, handler http.HandlerFunc) *endpoint {
	t.Helper()
	e := &endpoint{}
	recording := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		e.mu.Lock()
		e.requests = append(e.requests, received{header: r.Header.Clone(), body: body})
		e.mu.Unlock()
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		handler(w, r)
	})
	if tls {
		e.server = httptest.NewTLSServer(recording)
	} else {
		e.server = httptest.NewServer(recording)
	}
	t.Cleanup(e.server.Close)
	return e
}

func (e *endpoint) received() []received {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.requests)
}

func status(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, "body of the endpoint\n")
	}
}

func newRelay(t *testing.T, o *webhook.Options) *webhook.Relay {
	t.Helper()
	r, err := webhook.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// decoded returns the records of the update section of a message, as tsigoat
// receives them.
func decoded(t *testing.T, build func(m *dns.Msg)) []dns.RR {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate(zone)
	build(m)
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	in := new(dns.Msg)
	if err := in.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	return in.Ns
}

func records(t *testing.T, texts ...string) []dns.RR {
	t.Helper()
	rrs := make([]dns.RR, 0, len(texts))
	for _, text := range texts {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		rrs = append(rrs, rr)
	}
	return rrs
}

func TestUpdatePostsTheOperations(t *testing.T) {
	t.Parallel()
	e := newEndpoint(t, false, status(http.StatusNoContent))
	relay := newRelay(t, &webhook.Options{URL: e.server.URL + "/hook", UserAgent: "tsigoat/test"})

	updates := decoded(t, func(m *dns.Msg) {
		m.Insert(records(t, `_acme-challenge.WWW.example.test. 60 IN TXT "value"`, "www.example.test. 0 IN A 192.0.2.1"))
		m.Remove(records(t, `txt.example.test. 300 IN TXT "stale" "two strings"`))
		m.RemoveRRset(records(t, "mx.example.test. 300 IN MX 10 mail.example.test."))
		m.RemoveName(records(t, "old.example.test. 300 IN A 192.0.2.2"))
		// RFC 2136 ignores these deletions.
		m.RemoveRRset(records(t, "example.test. 300 IN SOA ns1. hostmaster. 1 2 3 4 5", "example.test. 300 IN NS ns1."))
		m.Remove(records(t, "example.test. 300 IN SOA ns1. hostmaster. 1 2 3 4 5"))
	})
	rcode, err := relay.Update(t.Context(), zone, "acme.", nil, updates)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("Update() = %d, %v, want NOERROR", rcode, err)
	}

	requests := e.received()
	if len(requests) != 1 {
		t.Fatalf("%d requests, want 1", len(requests))
	}
	got := requests[0]
	if ct, ua := got.header.Get("Content-Type"), got.header.Get("User-Agent"); ct != "application/json" || ua != "tsigoat/test" {
		t.Errorf("Content-Type %q and User-Agent %q", ct, ua)
	}
	var request map[string]any
	if err := json.Unmarshal(got.body, &request); err != nil {
		t.Fatal(err)
	}
	want := `{"key":"acme.","operations":[` +
		`{"name":"_acme-challenge.www.example.test.","op":"add","rdata":"\"value\"","ttl":60,"type":"TXT"},` +
		`{"name":"www.example.test.","op":"add","rdata":"192.0.2.1","ttl":0,"type":"A"},` +
		`{"name":"txt.example.test.","op":"delete","rdata":"\"stale\" \"two strings\"","type":"TXT"},` +
		`{"name":"mx.example.test.","op":"delete","type":"MX"},` +
		`{"name":"old.example.test.","op":"delete"}],` +
		`"version":1,"zone":"example.test."}`
	if canonical, _ := json.Marshal(request); string(canonical) != want {
		t.Errorf("request\n%s\nwant\n%s", canonical, want)
	}
}

func TestAuthentication(t *testing.T) {
	t.Parallel()
	header := http.Header{}
	header.Set("X-Tenant", "dns")

	tests := []struct {
		name    string
		options webhook.Options
		check   func(t *testing.T, r received)
	}{
		{"signature", webhook.Options{SignatureSecret: "shared secret"}, func(t *testing.T, r received) {
			t.Helper()
			timestamp := r.header.Get(webhook.TimestampHeader)
			seconds, err := strconv.ParseInt(timestamp, 10, 64)
			if err != nil || time.Since(time.Unix(seconds, 0)).Abs() > time.Minute {
				t.Errorf("timestamp %q", timestamp)
			}
			if got, want := r.header.Get(webhook.SignatureHeader), webhook.Sign([]byte("shared secret"), timestamp, r.body); got != want {
				t.Errorf("signature %q, want %q", got, want)
			}
			if r.header.Get("Authorization") != "" {
				t.Error("an Authorization header came with the signature alone")
			}
		}},
		{"basic", webhook.Options{Username: "tsigoat", Password: "p@ss:word"}, func(t *testing.T, r received) {
			t.Helper()
			req := &http.Request{Header: r.header}
			if user, password, ok := req.BasicAuth(); !ok || user != "tsigoat" || password != "p@ss:word" {
				t.Errorf("basic credentials %q %q", user, password)
			}
		}},
		{"bearer", webhook.Options{BearerToken: "opaque"}, func(t *testing.T, r received) {
			t.Helper()
			if got := r.header.Get("Authorization"); got != "Bearer opaque" {
				t.Errorf("Authorization %q", got)
			}
		}},
		{"headers", webhook.Options{Header: header}, func(t *testing.T, r received) {
			t.Helper()
			if got := r.header.Get("X-Tenant"); got != "dns" {
				t.Errorf("X-Tenant %q", got)
			}
			if r.header.Get(webhook.SignatureHeader) != "" {
				t.Error("a signature came without a secret")
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEndpoint(t, false, status(http.StatusOK))
			options := tt.options
			options.URL = e.server.URL
			if err := newRelay(t, &options).Check(t.Context(), zone); err != nil {
				t.Fatalf("Check(): %v", err)
			}
			requests := e.received()
			if len(requests) != 1 {
				t.Fatalf("%d requests, want 1", len(requests))
			}
			tt.check(t, requests[0])
		})
	}
}

func TestFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		timeout time.Duration
		err     string
	}{
		{"client error", status(http.StatusUnauthorized), 0, "answered 401 Unauthorized: body of the endpoint"},
		{"server error", status(http.StatusInternalServerError), 0, "answered 500 Internal Server Error"},
		{"timeout", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			w.WriteHeader(http.StatusOK)
		}, 100 * time.Millisecond, "Timeout exceeded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := newEndpoint(t, false, tt.handler)
			relay := newRelay(t, &webhook.Options{URL: e.server.URL, Timeout: tt.timeout})
			_, err := relay.Update(t.Context(), zone, "", nil, records(t, `a.example.test. 60 IN TXT "x"`))
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("Update() error = %v, want one about %q", err, tt.err)
			}
		})
	}
}

func TestRejections(t *testing.T) {
	t.Parallel()
	e := newEndpoint(t, false, status(http.StatusOK))
	relay := newRelay(t, &webhook.Options{URL: e.server.URL})

	tests := []struct {
		name                   string
		prerequisites, updates []dns.RR
	}{
		{"prerequisites", records(t, "www.example.test. 0 IN A 192.0.2.1"), nil},
		{"deletion of the apex", nil, decoded(t, func(m *dns.Msg) { m.RemoveName(records(t, "example.test. 300 IN A 192.0.2.1")) })},
	}
	for _, tt := range tests {
		_, err := relay.Update(t.Context(), zone, "", tt.prerequisites, tt.updates)
		if rejection, ok := errors.AsType[*backend.RejectionError](err); !ok || rejection.Rcode != dns.RcodeRefused {
			t.Errorf("%s: Update() error = %v, want a REFUSED rejection", tt.name, err)
		}
	}
	// Ignored deletions alone make no request.
	updates := decoded(t, func(m *dns.Msg) { m.RemoveRRset(records(t, "example.test. 300 IN NS ns1.")) })
	if rcode, err := relay.Update(t.Context(), zone, "", nil, updates); rcode != dns.RcodeSuccess || err != nil {
		t.Errorf("Update() of ignored deletions = %d, %v, want NOERROR", rcode, err)
	}
	if requests := e.received(); len(requests) != 0 {
		t.Errorf("%d requests, want none", len(requests))
	}
}

func TestRedirects(t *testing.T) {
	t.Parallel()
	target := newEndpoint(t, false, status(http.StatusNoContent))
	redirect := func(code int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.server.URL, code)
		}
	}

	tests := []struct {
		code   int
		follow bool
		err    string
	}{
		{http.StatusTemporaryRedirect, false, "redirecting to " + target.server.URL},
		{http.StatusFound, true, "answered 302 Found, redirecting to " + target.server.URL},
		{http.StatusPermanentRedirect, true, ""},
	}
	for _, tt := range tests {
		e := newEndpoint(t, false, redirect(tt.code))
		relay := newRelay(t, &webhook.Options{URL: e.server.URL, FollowRedirects: tt.follow, SignatureSecret: "s"})
		err := relay.Check(t.Context(), zone)
		switch {
		case tt.err == "" && err != nil:
			t.Errorf("%d, follow %v: Check() = %v", tt.code, tt.follow, err)
		case tt.err != "" && (err == nil || !strings.Contains(err.Error(), tt.err)):
			t.Errorf("%d, follow %v: Check() error = %v, want one about %q", tt.code, tt.follow, err, tt.err)
		}
	}
	requests := target.received()
	if len(requests) != 1 {
		t.Fatalf("the target received %d requests, want 1", len(requests))
	}
	if r := requests[0]; len(r.body) == 0 || r.header.Get(webhook.SignatureHeader) == "" {
		t.Error("the redirected request lost its body or its signature")
	}
}

func TestTLS(t *testing.T) {
	t.Parallel()
	e := newEndpoint(t, true, status(http.StatusOK))
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := newRelay(t, &webhook.Options{URL: e.server.URL}).Check(t.Context(), zone); err == nil {
		t.Error("Check() trusted an unknown certificate")
	}
	for name, options := range map[string]webhook.Options{
		"CA file":              {URL: e.server.URL, CAFile: caFile},
		"insecure skip verify": {URL: e.server.URL, InsecureSkipVerify: true},
	} {
		if err := newRelay(t, &options).Check(t.Context(), zone); err != nil {
			t.Errorf("%s: Check(): %v", name, err)
		}
	}
}

// TestOneUpdateOfAZoneAtATime checks that the updates of a zone wait for each
// other, so that an endpoint never applies two at once.
func TestOneUpdateOfAZoneAtATime(t *testing.T) {
	t.Parallel()
	var running, most atomic.Int32
	e := newEndpoint(t, false, func(w http.ResponseWriter, _ *http.Request) {
		now := running.Add(1)
		for {
			previous := most.Load()
			if now <= previous || most.CompareAndSwap(previous, now) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		running.Add(-1)
		w.WriteHeader(http.StatusNoContent)
	})
	relay := newRelay(t, &webhook.Options{URL: e.server.URL})

	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			if _, err := relay.Update(t.Context(), zone, "", nil, records(t, `a.example.test. 60 IN TXT "x"`)); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := most.Load(); got != 1 {
		t.Errorf("%d updates of the zone ran at once, want 1", got)
	}
}

func TestCheckAndSOA(t *testing.T) {
	t.Parallel()
	e := newEndpoint(t, false, status(http.StatusNoContent))
	relay := newRelay(t, &webhook.Options{URL: e.server.URL})
	if err := relay.Check(t.Context(), zone); err != nil {
		t.Fatal(err)
	}
	if requests := e.received(); len(requests) != 1 ||
		string(requests[0].body) != `{"version":1,"zone":"example.test.","key":"","operations":[]}` {
		t.Errorf("check requests %q", requests)
	}

	soa, err := relay.SOA(t.Context(), zone)
	if err != nil || soa.Header().Name != zone || soa.Header().Rrtype != dns.TypeSOA {
		t.Errorf("SOA() = %v, %v, want a SOA of the zone", soa, err)
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	for _, url := range []string{"", "hooks.example.test", "ftp://hooks.example.test", "https://"} {
		if _, err := webhook.New(&webhook.Options{URL: url}); err == nil {
			t.Errorf("New(%q) succeeded", url)
		}
	}
	if _, err := webhook.New(&webhook.Options{URL: "https://hooks.example.test", CAFile: "/missing.pem"}); err == nil {
		t.Error("New() accepted a missing CA file")
	}
}
