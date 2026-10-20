package powerdns

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
)

const apiKey = "test-api-key" // gitleaks:allow

// fakeAPI imitates the zone endpoints of the PowerDNS API.
type fakeAPI struct {
	t *testing.T

	mu sync.Mutex
	// zones holds the RRsets of every zone, by zone ID.
	zones map[string][]rrset
	// patches records the bodies of the PATCH requests.
	patches []string
	// ignoreFilter imitates the versions without rrset_name.
	ignoreFilter bool
	// canonical, when set, gives the form PowerDNS writes some contents in:
	// a PATCH with another form is refused, as PowerDNS does.
	canonical map[string]string
	// failure, when set, answers every request.
	failure func(w http.ResponseWriter)
}

func newFakeAPI(t *testing.T) (*fakeAPI, *httptest.Server) {
	t.Helper()
	api := &fakeAPI{t: t, zones: map[string][]rrset{
		"example.test.": {
			{Name: "example.test.", Type: "SOA", TTL: 3600, Records: []record{{Content: "ns1.example.test. hostmaster.example.test. 1 10800 3600 604800 3600"}}},
			{Name: "example.test.", Type: "NS", TTL: 3600, Records: []record{{Content: "ns1.example.test."}}},
			{Name: "example.test.", Type: "ALIAS", TTL: 300, Records: []record{{Content: "lb.example.net."}}},
			{Name: "www.example.test.", Type: "A", TTL: 300, Records: []record{
				{Content: "192.0.2.1"}, {Content: "192.0.2.9", Disabled: true},
			}},
			{Name: "www.example.test.", Type: "TXT", TTL: 60, Records: []record{{Content: `"a b" "c\"d"`}}},
			{Name: "WWW.example.test.", Type: "MX", TTL: 60, Records: []record{{Content: "10 mail.example.test."}}},
			{Name: "www.example.test.", Type: "CAA", TTL: 60, Records: []record{{Content: `0 issue "letsencrypt.org"`}}},
			{Name: "off.example.test.", Type: "A", TTL: 60, Records: []record{{Content: "192.0.2.2", Disabled: true}}},
			{Name: "other.example.test.", Type: "A", TTL: 60, Records: []record{{Content: "192.0.2.3"}}},
		},
	}}
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	return api, server
}

func (a *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.failure != nil {
		a.failure(w)
		return
	}
	if r.Header.Get("X-API-Key") != apiKey {
		http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}
	id, ok := strings.CutPrefix(r.URL.Path, "/api/v1/servers/localhost/zones/")
	sets, known := a.zones[id]
	if !ok || !known {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error": "Could not find domain '`+id+`'"}`)
		return
	}

	switch r.Method {
	case http.MethodGet:
		name := r.URL.Query().Get("rrset_name")
		var selected []rrset
		for _, set := range sets {
			if a.ignoreFilter || name == "" || strings.EqualFold(set.Name, name) {
				selected = append(selected, set)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"name": id, "rrsets": selected})
	case http.MethodPatch:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			a.t.Error(err)
		}
		a.patches = append(a.patches, string(body))
		var patch struct {
			RRsets []rrset `json:"rrsets"`
		}
		if err := json.Unmarshal(body, &patch); err != nil {
			a.t.Error(err)
		}
		for _, set := range patch.RRsets {
			for _, rec := range set.Records {
				if canonical, ok := a.canonical[rec.Content]; ok && canonical != rec.Content {
					w.WriteHeader(http.StatusUnprocessableEntity)
					_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf(
						"Record %s/%s '%s': Not in expected format (parsed as '%s')", set.Name, set.Type, rec.Content, canonical)})
					return
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
	}
}

func newBackend(t *testing.T, url string) *Backend {
	t.Helper()
	b, err := New(&Options{URL: url + "/", APIKey: apiKey, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func describe(sets []backend.RRset) string {
	var lines []string
	for _, set := range sets {
		for _, rr := range set.Records {
			lines = append(lines, strings.Join(strings.Fields(rr.String()), " "))
		}
	}
	return strings.Join(lines, "\n")
}

func TestLookup(t *testing.T) {
	t.Parallel()

	for _, ignoreFilter := range []bool{false, true} {
		api, server := newFakeAPI(t)
		api.ignoreFilter = ignoreFilter
		b := newBackend(t, server.URL)

		sets, err := b.Lookup(t.Context(), "example.test.", "WWW.Example.Test.")
		if err != nil {
			t.Fatal(err)
		}
		want := strings.Join([]string{
			"www.example.test. 300 IN A 192.0.2.1",
			`www.example.test. 60 IN TXT "a b" "c\"d"`,
			"www.example.test. 60 IN MX 10 mail.example.test.",
			`www.example.test. 60 IN CAA 0 issue "letsencrypt.org"`,
		}, "\n")
		if got := describe(sets); got != want {
			t.Errorf("ignoreFilter=%v: Lookup():\n%s\nwant:\n%s", ignoreFilter, got, want)
		}

		// A name whose only records are disabled owns nothing.
		sets, err = b.Lookup(t.Context(), "example.test.", "off.example.test.")
		if err != nil || len(sets) != 0 {
			t.Errorf("Lookup() of disabled records = %v, %v, want nothing", sets, err)
		}
	}
}

func TestLookupOpaqueTypes(t *testing.T) {
	t.Parallel()
	_, server := newFakeAPI(t)
	b := newBackend(t, server.URL)

	sets, err := b.Lookup(t.Context(), "example.test.", "example.test.")
	if err != nil {
		t.Fatal(err)
	}
	var alias *backend.RRset
	for i := range sets {
		if sets[i].Type == typeALIAS {
			alias = &sets[i]
		}
	}
	if alias == nil || len(alias.Records) != 1 {
		t.Fatalf("Lookup() = %v, want the ALIAS RRset", sets)
	}

	// Deleting it works, writing it does not.
	if deleteErr := b.Apply(t.Context(), "example.test.", []backend.Change{{Op: backend.Delete, RRset: *alias}}); deleteErr != nil {
		t.Errorf("deleting an ALIAS RRset: %v", deleteErr)
	}
	err = b.Apply(t.Context(), "example.test.", []backend.Change{{Op: backend.Replace, RRset: *alias}})
	if err == nil || !strings.Contains(err.Error(), "cannot write ALIAS") {
		t.Errorf("writing an ALIAS RRset: error %v", err)
	}
}

func TestApply(t *testing.T) {
	t.Parallel()
	api, server := newFakeAPI(t)
	b := newBackend(t, server.URL)

	records := func(lines ...string) []dns.RR {
		rrs := make([]dns.RR, 0, len(lines))
		for _, line := range lines {
			rr, err := dns.NewRR(line)
			if err != nil {
				t.Fatal(err)
			}
			rrs = append(rrs, rr)
		}
		return rrs
	}
	err := b.Apply(t.Context(), "example.test.", []backend.Change{
		{Op: backend.Replace, RRset: backend.RRset{
			Name: "_acme-challenge.www.example.test.", Type: dns.TypeTXT, TTL: 60,
			Records: records(`x. 60 IN TXT "token one"`, `x. 60 IN TXT "with \"quotes\""`),
		}},
		{Op: backend.Delete, RRset: backend.RRset{Name: "www.example.test.", Type: dns.TypeA}},
		{Op: backend.Replace, RRset: backend.RRset{
			Name: "new.example.test.", Type: 65534, TTL: 30,
			Records: []dns.RR{&dns.RFC3597{Hdr: dns.RR_Header{Rrtype: 65534, Class: dns.ClassINET}, Rdata: "0a000001"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(api.patches) != 1 {
		t.Fatalf("%d PATCH requests, want 1", len(api.patches))
	}
	want := `{"rrsets":[` +
		`{"name":"_acme-challenge.www.example.test.","type":"TXT","ttl":60,"changetype":"REPLACE","records":[` +
		`{"content":"\"token one\"","disabled":false},{"content":"\"with \\\"quotes\\\"\"","disabled":false}]},` +
		`{"name":"www.example.test.","type":"A","changetype":"DELETE","records":null},` +
		`{"name":"new.example.test.","type":"TYPE65534","ttl":30,"changetype":"REPLACE","records":[` +
		`{"content":"\\# 4 0a000001","disabled":false}]}]}`
	if api.patches[0] != want {
		t.Errorf("PATCH body:\n%s\nwant:\n%s", api.patches[0], want)
	}

	if err := b.Apply(t.Context(), "example.test.", nil); err != nil || len(api.patches) != 1 {
		t.Errorf("Apply() without changes: %v, %d requests", err, len(api.patches))
	}
}

func TestApplyReformats(t *testing.T) {
	t.Parallel()

	const (
		sent      = "48 51 24.000 N 02 21 3.000 E 35m 10m 100m 10m"
		canonical = "48 51 24.000 N 2 21 3.000 E 35.00m 10.00m 100.00m 10.00m"
	)
	loc := func(text string) backend.Change {
		rr, err := dns.NewRR("office.example.test. 300 IN LOC " + text)
		if err != nil {
			t.Fatal(err)
		}
		return backend.Change{Op: backend.Replace, RRset: backend.RRset{
			Name: "office.example.test.", Type: dns.TypeLOC, TTL: 300, Records: []dns.RR{rr},
		}}
	}

	api, server := newFakeAPI(t)
	api.canonical = map[string]string{sent: canonical}
	b := newBackend(t, server.URL)
	if err := b.Apply(t.Context(), "example.test.", []backend.Change{loc(sent)}); err != nil {
		t.Fatalf("Apply() = %v", err)
	}
	if len(api.patches) != 2 || !strings.Contains(api.patches[1], canonical) {
		t.Errorf("PATCH requests %q, want a second one with the canonical form", api.patches)
	}

	// A form that is not the same RDATA is not sent again.
	api, server = newFakeAPI(t)
	api.canonical = map[string]string{sent: "48 51 24.000 N 2 21 3.000 E 99.00m 10.00m 100.00m 10.00m"}
	b = newBackend(t, server.URL)
	err := b.Apply(t.Context(), "example.test.", []backend.Change{loc(sent)})
	if err == nil || len(api.patches) != 1 {
		t.Errorf("Apply() = %v after %d requests, want the error of the first one", err, len(api.patches))
	}
}

func TestContent(t *testing.T) {
	t.Parallel()

	for text, want := range map[string]string{
		"x. 60 IN A 192.0.2.1":                        "192.0.2.1",
		`x. 60 IN HTTPS 1 . alpn="h2,h3" port="8443"`: "1 . alpn=h2,h3 port=8443",
		`x. 60 IN SVCB 1 svc.example. mandatory=alpn alpn=h2 no-default-alpn ipv4hint=192.0.2.1,192.0.2.2`: "1 svc.example. mandatory=alpn alpn=h2 no-default-alpn ipv4hint=192.0.2.1,192.0.2.2",
		`x. 60 IN HTTPS 0 svc.example.`: "0 svc.example.",
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		if got := content(rr); got != want {
			t.Errorf("content(%s) = %q, want %q", text, got, want)
		}
		// PowerDNS writes it back that way: it must parse to the same record.
		back, err := parseContent("x.", 60, rr.Header().Rrtype, want)
		if err != nil || !dns.IsDuplicate(rr, back) {
			t.Errorf("parsing %q back: %v, %v", want, back, err)
		}
	}
}

func TestErrors(t *testing.T) {
	t.Parallel()

	t.Run("unknown zone", func(t *testing.T) {
		t.Parallel()
		_, server := newFakeAPI(t)
		b := newBackend(t, server.URL)
		_, err := b.Lookup(t.Context(), "nowhere.test.", "nowhere.test.")
		apiErr, ok := errors.AsType[*APIError](err)
		if !errors.Is(err, backend.ErrZoneNotFound) || !ok || apiErr.Status != http.StatusNotFound {
			t.Errorf("error %v, want ErrZoneNotFound and an APIError", err)
		}
		if !strings.Contains(err.Error(), "Could not find domain") {
			t.Errorf("error %q lacks the message of the API", err)
		}
	})

	t.Run("wrong API key", func(t *testing.T) {
		t.Parallel()
		_, server := newFakeAPI(t)
		b, err := New(&Options{URL: server.URL, APIKey: "wrong"})
		if err != nil {
			t.Fatal(err)
		}
		_, err = b.Lookup(t.Context(), "example.test.", "example.test.")
		apiErr, ok := errors.AsType[*APIError](err)
		if !ok || apiErr.Status != http.StatusUnauthorized || apiErr.Message != "Unauthorized" {
			t.Errorf("error %v, want HTTP 401 Unauthorized", err)
		}
	})

	t.Run("invalid record", func(t *testing.T) {
		t.Parallel()
		api, server := newFakeAPI(t)
		api.failure = func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = io.WriteString(w, `{"error": "Record x./A '1.2.3': Parsing record content"}`)
		}
		b := newBackend(t, server.URL)
		err := b.Apply(t.Context(), "example.test.", []backend.Change{{Op: backend.Delete, RRset: backend.RRset{Name: "x.example.test.", Type: dns.TypeA}}})
		if err == nil || !strings.Contains(err.Error(), "HTTP 422: Record x./A") {
			t.Errorf("error %v, want the message of the API", err)
		}
	})

	t.Run("unparsable content", func(t *testing.T) {
		t.Parallel()
		api, server := newFakeAPI(t)
		api.zones["example.test."] = append(api.zones["example.test."], rrset{
			Name: "bad.example.test.", Type: "A", TTL: 60, Records: []record{{Content: "not an address"}},
		})
		b := newBackend(t, server.URL)
		if _, err := b.Lookup(t.Context(), "example.test.", "bad.example.test."); err == nil {
			t.Error("Lookup() accepted invalid content")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
		t.Cleanup(server.Close)
		t.Cleanup(func() { close(release) })
		b, err := New(&Options{URL: server.URL, APIKey: apiKey, Timeout: 50 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, err := b.Lookup(t.Context(), "example.test.", "example.test."); err == nil {
			t.Error("Lookup() succeeded")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("Lookup() returned after %s", elapsed)
		}
	})
}

func TestCAFile(t *testing.T) {
	t.Parallel()

	api := &fakeAPI{t: t, zones: map[string][]rrset{"example.test.": nil}}
	server := httptest.NewTLSServer(api)
	t.Cleanup(server.Close)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}

	untrusted, err := New(&Options{URL: server.URL, APIKey: apiKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, lookupErr := untrusted.Lookup(t.Context(), "example.test.", "example.test."); lookupErr == nil {
		t.Error("Lookup() trusted an unknown certificate")
	}

	trusted, err := New(&Options{URL: server.URL, APIKey: apiKey, CAFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trusted.Lookup(t.Context(), "example.test.", "example.test."); err != nil {
		t.Errorf("Lookup() with the CA file: %v", err)
	}

	if _, err := New(&Options{URL: server.URL, CAFile: filepath.Join(t.TempDir(), "missing.pem")}); err == nil {
		t.Error("New() accepted a missing CA file")
	}
	if err := os.WriteFile(caFile, []byte("no certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(&Options{URL: server.URL, CAFile: caFile}); err == nil {
		t.Error("New() accepted a CA file without certificates")
	}
}

func TestNewInvalidURL(t *testing.T) {
	t.Parallel()
	for _, url := range []string{"", "pdns:8081", "ftp://pdns", "http://"} {
		if _, err := New(&Options{URL: url}); err == nil {
			t.Errorf("New() accepted URL %q", url)
		}
	}
}

func TestZoneID(t *testing.T) {
	t.Parallel()
	for zone, want := range map[string]string{
		"example.test.":     "example.test.",
		"Example.Test":      "Example.Test.",
		"_sub.example.":     "=5Fsub.example.",
		"2/24.2.0.192.arpa": "2=2F24.2.0.192.arpa.",
		".":                 "=2E",
	} {
		if got := zoneID(zone); got != want {
			t.Errorf("zoneID(%q) = %q, want %q", zone, got, want)
		}
	}
}
