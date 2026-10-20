package webhook_test

import (
	"encoding/hex"
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

// validID reports whether id is the identifier of a request: 128 bits in
// hexadecimal.
func validID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && id == strings.ToLower(id)
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
	if id, _ := request["id"].(string); !validID(id) {
		t.Errorf("id %q, want 32 hexadecimal digits", id)
	}
	delete(request, "id")
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
		// indeterminate tells that the endpoint may have applied the
		// update.
		indeterminate bool
	}{
		{"client error", status(http.StatusUnauthorized), 0, "answered 401 Unauthorized: body of the endpoint", false},
		{"server error", status(http.StatusInternalServerError), 0, "answered 500 Internal Server Error", false},
		{"bad gateway", status(http.StatusBadGateway), 0, "answered 502 Bad Gateway", true},
		{"gateway timeout", status(http.StatusGatewayTimeout), 0, "answered 504 Gateway Timeout", true},
		{"timeout", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			w.WriteHeader(http.StatusOK)
		}, 100 * time.Millisecond, "Timeout exceeded", true},
		{"connection closed without a response", func(w http.ResponseWriter, _ *http.Request) {
			if hijacker, ok := w.(http.Hijacker); ok {
				if conn, _, err := hijacker.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
		}, 0, "posting the update", true},
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
			if backend.IsIndeterminate(err) != tt.indeterminate {
				t.Errorf("Update() error = %v, indeterminate %t, want %t", err, backend.IsIndeterminate(err), tt.indeterminate)
			}
			// A check changes nothing: its outcome is never unknown.
			if err := relay.Check(t.Context(), zone); err == nil || backend.IsIndeterminate(err) {
				t.Errorf("Check() error = %v, want a plain failure", err)
			}
		})
	}
}

// TestUnreachable checks that a request that never left gives a plain
// failure: the endpoint cannot have applied it.
func TestUnreachable(t *testing.T) {
	t.Parallel()
	e := newEndpoint(t, false, status(http.StatusNoContent))
	url := e.server.URL
	e.server.Close()
	_, err := newRelay(t, &webhook.Options{URL: url}).Update(t.Context(), zone, "", nil, records(t, `a.example.test. 60 IN TXT "x"`))
	if err == nil || backend.IsIndeterminate(err) {
		t.Errorf("Update() error = %v, want a plain failure", err)
	}
}

// TestStatusIsTheAnswer checks that the status of a success is the answer of
// the endpoint: tsigoat does not wait for a body that stalls.
func TestStatusIsTheAnswer(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	e := newEndpoint(t, false, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "the start of a body")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-release
	})
	// Cleanups run last first: the handler returns before the server stops.
	t.Cleanup(func() { close(release) })
	relay := newRelay(t, &webhook.Options{URL: e.server.URL, Timeout: 5 * time.Second})
	start := time.Now()
	if _, err := relay.Update(t.Context(), zone, "", nil, records(t, `a.example.test. 60 IN TXT "x"`)); err != nil {
		t.Fatalf("Update() = %v, want a success", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Update() returned after %s, waiting for the body", elapsed)
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

// TestRedirects checks that the relay follows, on request, the 307 and 308
// redirects to the same scheme and host alone: another origin would get the
// headers of the request.
func TestRedirects(t *testing.T) {
	t.Parallel()
	other := newEndpoint(t, false, status(http.StatusNoContent))
	var final atomic.Int32
	e := newEndpoint(t, false, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/final":
			if r.Header.Get(webhook.SignatureHeader) == "" {
				http.Error(w, "the redirected request lost its signature", http.StatusUnauthorized)
				return
			}
			final.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case "/other":
			http.Redirect(w, r, other.server.URL+"/final", http.StatusTemporaryRedirect)
		default:
			code, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
			http.Redirect(w, r, "/final", code)
		}
	})

	tests := []struct {
		path   string
		follow bool
		err    string
	}{
		{"/307", false, "redirecting to /final: set the URL to the final address, or followRedirects"},
		{"/302", true, "answered 302 Found, redirecting to /final"},
		{"/307", true, ""},
		{"/308", true, ""},
		{"/other", true, "answered 307 Temporary Redirect, redirecting to " + other.server.URL},
	}
	for _, tt := range tests {
		relay := newRelay(t, &webhook.Options{URL: e.server.URL + tt.path, FollowRedirects: tt.follow, SignatureSecret: "s"})
		err := relay.Check(t.Context(), zone)
		switch {
		case tt.err == "" && err != nil:
			t.Errorf("%s, follow %v: Check() = %v", tt.path, tt.follow, err)
		case tt.err != "" && (err == nil || !strings.Contains(err.Error(), tt.err)):
			t.Errorf("%s, follow %v: Check() error = %v, want one about %q", tt.path, tt.follow, err, tt.err)
		}
	}
	if got := final.Load(); got != 2 {
		t.Errorf("%d requests reached the final address, want 2", got)
	}
	if requests := other.received(); len(requests) != 0 {
		t.Errorf("another origin received %d requests", len(requests))
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
// other, so that an endpoint that answers within the timeout never applies
// two at once.
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
	for range 2 {
		if err := relay.Check(t.Context(), zone); err != nil {
			t.Fatal(err)
		}
	}
	requests := e.received()
	if len(requests) != 2 {
		t.Fatalf("%d check requests, want 2", len(requests))
	}
	ids := make([]string, 0, len(requests))
	for _, r := range requests {
		var request webhook.Request
		if err := json.Unmarshal(r.body, &request); err != nil {
			t.Fatal(err)
		}
		if !validID(request.ID) || request.Version != 1 || request.Zone != zone || request.Key != "" ||
			request.Operations == nil || len(request.Operations) != 0 {
			t.Errorf("check request %s", r.body)
		}
		ids = append(ids, request.ID)
	}
	if ids[0] == ids[1] {
		t.Errorf("two requests share the identifier %s", ids[0])
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
