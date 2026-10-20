package scaleway_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/backendtest"
	"github.com/enix/tsigoat/internal/backend/scaleway"
	"github.com/enix/tsigoat/internal/backend/scaleway/scalewaytest"
)

const testZone = "example.test."

func rr(t *testing.T, text string) dns.RR {
	t.Helper()
	parsed, err := dns.NewRR(text)
	if err != nil || parsed == nil {
		t.Fatalf("parsing %q: %v", text, err)
	}
	return parsed
}

// newBackend returns a backend on a simulated API that holds testZone.
func newBackend(t *testing.T) (*scaleway.Backend, *scalewaytest.API) {
	t.Helper()
	api := scalewaytest.New(t)
	api.CreateZone(testZone)
	b, err := scaleway.New(&scaleway.Options{URL: api.URL, SecretKey: scalewaytest.SecretKey})
	if err != nil {
		t.Fatal(err)
	}
	return b, api
}

// replace returns a change that replaces an RRset with records, which give it
// their name, type and TTL.
func replace(t *testing.T, lines ...string) backend.Change {
	t.Helper()
	var set backend.RRset
	for _, line := range lines {
		record := rr(t, line)
		set.Name, set.Type, set.TTL = dns.CanonicalName(record.Header().Name), record.Header().Rrtype, record.Header().Ttl
		set.Records = append(set.Records, record)
	}
	return backend.Change{Op: backend.Replace, RRset: set}
}

// TestConformance runs the conformance suite of the backends on the
// simulated API.
func TestConformance(t *testing.T) {
	t.Parallel()
	b, _ := newBackend(t)
	suite := &backendtest.Suite{
		Backend:  b,
		Zone:     testZone,
		Base:     "conformance." + testZone,
		Rejected: scalewaytest.Rejected(),
		Failing:  scalewaytest.Failing,
	}
	suite.Run(t)
}

func TestToAPI(t *testing.T) {
	t.Parallel()
	for text, want := range map[string]string{
		"www.example.test. 300 IN A 192.0.2.1":                 `{"name":"www","type":"A","data":"192.0.2.1","priority":0,"ttl":300}`,
		"example.test. 300 IN MX 10 mail.example.net.":         `{"name":"","type":"MX","data":"10 mail.example.net.","priority":0,"ttl":300}`,
		`www.example.test. 300 IN TXT "v=spf1 -all"`:           `{"name":"www","type":"TXT","data":"\"v=spf1 -all\"","priority":0,"ttl":300}`,
		`example.test. 300 IN HTTPS 1 . alpn="h2,h3" port=443`: `{"name":"","type":"HTTPS","data":"1 . alpn=h2,h3 port=443","priority":0,"ttl":300}`,
	} {
		got, _ := json.Marshal(scaleway.ToAPI(rr(t, text), testZone))
		if string(got) != want {
			t.Errorf("ToAPI(%s) =\n%s\nwant\n%s", text, got, want)
		}
	}
	long := strings.Repeat("a", 255)
	got := scaleway.ToAPI(rr(t, `www.example.test. 300 IN TXT "`+long+`" "b"`), testZone)
	if got.Data != `"`+long+`b"` {
		t.Errorf("ToAPI() of a long TXT record = %q, want a single string", got.Data)
	}
}

// TestReading checks the records that tsigoat reads: the names that the
// filter of the API matches too, the apex, which it does not filter, the
// dynamic records.
func TestReading(t *testing.T) {
	t.Parallel()
	b, api := newBackend(t)
	for _, r := range []scaleway.APIRecord{
		{Name: "www", Type: "TXT", Data: `"value"`, TTL: 300},
		{Name: "www2", Type: "TXT", Data: `"other"`, TTL: 300},
		{Name: "", Type: "MX", Data: "10 mail.example.net.", Priority: 10, TTL: 300},
		{Name: "geo", Type: "A", Data: "192.0.2.1", TTL: 300, WeightedConfig: json.RawMessage(`{"weighted_ips":[]}`)},
		{Name: "alias", Type: "ALIAS", Data: "target.example.net.", TTL: 300},
	} {
		api.AddRaw(testZone, &r)
	}
	for i := range 30 {
		api.AddRaw(testZone, &scaleway.APIRecord{Name: "bulk", Type: "TXT", Data: `"` + strings.Repeat("x", i+1) + `"`, TTL: 300})
	}

	sets, err := b.Lookup(t.Context(), testZone, "www."+testZone)
	if err != nil || len(sets) != 1 || len(sets[0].Records) != 1 {
		t.Errorf("Lookup(www) = %v, %v, want the record of the exact name", sets, err)
	}
	sets, err = b.Lookup(t.Context(), testZone, "bulk."+testZone)
	if err != nil || len(sets) != 1 || len(sets[0].Records) != 30 {
		t.Errorf("Lookup(bulk) = %v, %v, want 30 records over two pages", sets, err)
	}
	apex, err := b.Lookup(t.Context(), testZone, testZone)
	if err != nil {
		t.Fatal(err)
	}
	types := map[uint16]int{}
	for _, set := range apex {
		types[set.Type] = len(set.Records)
	}
	if types[dns.TypeSOA] != 1 || types[dns.TypeNS] != 2 || types[dns.TypeMX] != 1 || len(types) != 3 {
		t.Errorf("Lookup() of the apex = %v, want the SOA, the two NS records and the MX record", apex)
	}
	if alias, aliasErr := b.Lookup(t.Context(), testZone, "alias."+testZone); aliasErr != nil || len(alias) != 0 {
		t.Errorf("Lookup(alias) = %v, %v, want nothing", alias, aliasErr)
	}

	err = b.Apply(t.Context(), testZone, []backend.Change{replace(t, "geo.example.test. 300 IN A 192.0.2.2")})
	if rejection, ok := errors.AsType[*backend.RejectionError](err); !ok || !strings.Contains(rejection.Reason, "dynamic record") {
		t.Errorf("Apply() on a dynamic record = %v, want a rejection", err)
	}
}

func TestAmbiguousOutcome(t *testing.T) {
	t.Parallel()
	b, api := newBackend(t)
	api.FailPatch(0, "")
	if err := b.Apply(t.Context(), testZone, []backend.Change{replace(t, `www.example.test. 300 IN TXT "a"`)}); err != nil {
		t.Errorf("Apply() = %v, want a success read back", err)
	}
	api.FailPatch(http.StatusServiceUnavailable, "maintenance")
	err := b.Apply(t.Context(), testZone, []backend.Change{replace(t, `www.example.test. 300 IN TXT "b"`)})
	if err == nil || !strings.Contains(err.Error(), "do not show the update") {
		t.Errorf("Apply() = %v, want the failure, read back", err)
	}
}

func TestErrors(t *testing.T) {
	t.Parallel()
	b, api := newBackend(t)
	if _, err := b.Lookup(t.Context(), "other.test.", "other.test."); !errors.Is(err, backend.ErrZoneNotFound) {
		t.Errorf("Lookup() of an unknown zone = %v, want ErrZoneNotFound", err)
	}
	for _, change := range []backend.Change{
		replace(t, `www.example.test. 300 IN TXT "a" "b"`),
		replace(t, "sub.example.test. 300 IN NS ns.example.net."),
		replace(t, "www.example.test. 300 IN PTR host.example.net."),
	} {
		err := b.Apply(t.Context(), testZone, []backend.Change{change})
		if _, ok := errors.AsType[*backend.RejectionError](err); !ok {
			t.Errorf("Apply(%s) = %v, want a rejection", change, err)
		}
	}
	wrong, err := scaleway.New(&scaleway.Options{URL: api.URL, SecretKey: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Lookup(t.Context(), testZone, testZone); err == nil || !strings.Contains(err.Error(), "authentication is denied") {
		t.Errorf("Lookup() with a wrong key = %v", err)
	}
	if _, err := scaleway.New(&scaleway.Options{}); err == nil {
		t.Error("New() without a secret key succeeded")
	}
}
