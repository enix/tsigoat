package ovh_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/backendtest"
	"github.com/enix/tsigoat/internal/backend/ovh"
	"github.com/enix/tsigoat/internal/backend/ovh/ovhtest"
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

// newBackend returns a backend that signs its requests, on a simulated API
// that holds testZone with the records.
func newBackend(t *testing.T, records ...dns.RR) (*ovh.Backend, *ovhtest.API) {
	t.Helper()
	api := ovhtest.New(t)
	api.CreateZone(testZone, records...)
	b, err := ovh.New(&ovh.Options{
		Endpoint:       api.URL,
		ApplicationKey: ovhtest.ApplicationKey, ApplicationSecret: ovhtest.ApplicationSecret, ConsumerKey: ovhtest.ConsumerKey,
	})
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
		Rejected: ovhtest.Rejected(),
		Failing:  ovhtest.Failing,
	}
	suite.Run(t)
}

func TestServiceAccount(t *testing.T) {
	t.Parallel()
	api := ovhtest.New(t)
	api.CreateZone(testZone)
	b, err := ovh.New(&ovh.Options{
		Endpoint: api.URL, ClientID: ovhtest.ClientID, ClientSecret: ovhtest.ClientSecret, TokenURL: api.URL + ovhtest.TokenPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if applyErr := b.Apply(t.Context(), testZone, []backend.Change{replace(t, `www.example.test. 300 IN TXT "a"`)}); applyErr != nil {
			t.Fatal(applyErr)
		}
	}
	if api.Tokens() != 1 {
		t.Errorf("%d tokens issued, want one, kept for the second update", api.Tokens())
	}

	b, err = ovh.New(&ovh.Options{
		Endpoint: api.URL, ClientID: ovhtest.ClientID, ClientSecret: "wrong", TokenURL: api.URL + ovhtest.TokenPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Lookup(t.Context(), testZone, testZone); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("Lookup() with a wrong secret = %v", err)
	}
}

// TestClock checks that the signatures carry the time of the API, and that a
// request signed out of time goes again once the clock is read again.
func TestClock(t *testing.T) {
	t.Parallel()
	b, api := newBackend(t)
	api.SetSkew(time.Hour)
	if _, err := b.Lookup(t.Context(), testZone, "www."+testZone); err != nil {
		t.Fatalf("Lookup() with a skewed API clock: %v", err)
	}
	api.SetSkew(-time.Hour)
	if _, err := b.Lookup(t.Context(), testZone, "www."+testZone); err != nil {
		t.Errorf("Lookup() after the API clock moved: %v", err)
	}
}

// TestPublication checks that an update is published by one refresh, and that
// an update that fails is undone and not published.
func TestPublication(t *testing.T) {
	t.Parallel()
	b, api := newBackend(t, rr(t, `www.example.test. 300 IN TXT "kept"`))
	ctx := t.Context()
	refreshes := api.Refreshes()
	change := []backend.Change{replace(t, `www.example.test. 300 IN TXT "a"`, `www.example.test. 300 IN TXT "b"`)}
	if err := b.Apply(ctx, testZone, change); err != nil {
		t.Fatal(err)
	}
	if api.Refreshes() != refreshes+1 || !published(api, `"a"`) || !published(api, `"b"`) || published(api, `"kept"`) {
		t.Errorf("after an update: %d refreshes, published %v", api.Refreshes()-refreshes, api.Published(testZone))
	}

	// The third write, the second creation, fails: the deletion and the
	// first creation are undone, and nothing is published.
	before := api.Records(testZone)
	api.FailWrites([2]any{0, ""}, [2]any{0, ""}, [2]any{http.StatusBadRequest, "injected failure"})
	err := b.Apply(ctx, testZone, []backend.Change{replace(t, `www.example.test. 300 IN TXT "c"`, `www.example.test. 300 IN TXT "d"`)})
	if err == nil || !strings.Contains(err.Error(), "injected failure") || !strings.Contains(err.Error(), "were undone") {
		t.Errorf("Apply() = %v, want the failure, undone", err)
	}
	if !sameTargets(api.Records(testZone), before) || published(api, `"c"`) {
		t.Errorf("after a failed update: records %v, published %v", api.Records(testZone), api.Published(testZone))
	}

	// The refresh fails three times: the update is undone.
	api.FailWrites([2]any{0, ""}, [2]any{0, ""}, [2]any{0, ""},
		[2]any{http.StatusConflict, "refresh in progress"}, [2]any{http.StatusConflict, "refresh in progress"},
		[2]any{http.StatusConflict, "refresh in progress"})
	err = b.Apply(ctx, testZone, []backend.Change{replace(t, `www.example.test. 300 IN TXT "e"`)})
	if err == nil || !strings.Contains(err.Error(), "refreshing the zone") {
		t.Errorf("Apply() = %v, want the failure of the refresh", err)
	}
	if !sameTargets(api.Records(testZone), before) {
		t.Errorf("after a failed refresh: records %v, want them undone", api.Records(testZone))
	}
}

func published(api *ovhtest.API, target string) bool {
	for _, r := range api.Published(testZone) {
		if r.Target == target {
			return true
		}
	}
	return false
}

// sameTargets reports whether two lists of records hold the same records,
// whatever their identifiers.
func sameTargets(a, b []ovhtest.Record) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[string]int{}
	for _, r := range a {
		count[r.SubDomain+" "+r.FieldType+" "+r.Target]++
	}
	for _, r := range b {
		count[r.SubDomain+" "+r.FieldType+" "+r.Target]--
	}
	for _, n := range count {
		if n != 0 {
			return false
		}
	}
	return true
}

// TestReading checks the records that tsigoat reads: the names that the
// filter of the API matches too, the default TTL, the TXT types of OVHcloud,
// the unquoted TXT targets, the relative names.
func TestReading(t *testing.T) {
	t.Parallel()
	b, api := newBackend(t,
		rr(t, `_acme-challenge.example.test. 300 IN TXT "value"`),
		rr(t, `xacme-challenge.example.test. 300 IN TXT "other"`),
	)
	sets, err := b.Lookup(t.Context(), testZone, "_acme-challenge."+testZone)
	if err != nil || len(sets) != 1 || len(sets[0].Records) != 1 {
		t.Fatalf("Lookup() = %v, %v, want the record of the exact name", sets, err)
	}

	api.CreateZone(testZone)
	for _, r := range []ovhtest.Record{
		{FieldType: "SPF", SubDomain: "mail", Target: `"v=spf1 -all"`},
		{FieldType: "DMARC", SubDomain: "_dmarc", Target: "v=DMARC1; p=none"},
		{FieldType: "TXT", SubDomain: "legacy", Target: `unquoted "text"`},
		{FieldType: "CNAME", SubDomain: "alias", Target: "www"},
		{FieldType: "MX", SubDomain: "", Target: "10 mail"},
	} {
		api.AddRaw(testZone, &r)
	}
	for name, want := range map[string]string{
		"mail.example.test.":   "mail.example.test.\t3600\tIN\tTXT\t\"v=spf1 -all\"",
		"_dmarc.example.test.": "_dmarc.example.test.\t3600\tIN\tTXT\t\"v=DMARC1; p=none\"",
		"legacy.example.test.": "legacy.example.test.\t3600\tIN\tTXT\t\"unquoted \\\"text\\\"\"",
		"alias.example.test.":  "alias.example.test.\t3600\tIN\tCNAME\twww.example.test.",
	} {
		named, lookupErr := b.Lookup(t.Context(), testZone, name)
		if lookupErr != nil || len(named) != 1 || named[0].Records[0].String() != want {
			t.Errorf("Lookup(%s) = %v, %v, want %s", name, named, lookupErr, want)
		}
	}
	apex, err := b.Lookup(t.Context(), testZone, testZone)
	if err != nil {
		t.Fatal(err)
	}
	types := map[uint16]int{}
	for _, set := range apex {
		types[set.Type] = len(set.Records)
	}
	if types[dns.TypeSOA] != 1 || types[dns.TypeNS] != 2 || types[dns.TypeMX] != 1 {
		t.Errorf("Lookup() of the apex = %v, want the SOA, the two NS records and the MX record", apex)
	}
}

func TestErrors(t *testing.T) {
	t.Parallel()
	b, _ := newBackend(t)
	if _, err := b.Lookup(t.Context(), "other.test.", "other.test."); !errors.Is(err, backend.ErrZoneNotFound) ||
		!strings.Contains(err.Error(), "This service does not exist (query EU.ext-1.test)") {
		t.Errorf("Lookup() of an unknown zone = %v", err)
	}
	for _, change := range []backend.Change{
		replace(t, "example.test. 300 IN NS ns.example.net."),
		replace(t, `www.example.test. 300 IN TXT "a\"b"`),
		replace(t, `www.example.test. 30 IN TXT "low"`),
		replace(t, "www.example.test. 300 IN DS 1 13 2 00ab"),
	} {
		err := b.Apply(t.Context(), testZone, []backend.Change{change})
		if _, ok := errors.AsType[*backend.RejectionError](err); !ok {
			t.Errorf("Apply(%s) = %v, want a rejection", change, err)
		}
	}
	for _, options := range []ovh.Options{
		{Endpoint: "ftp://example.test", ApplicationKey: "k", ApplicationSecret: "s", ConsumerKey: "c"},
		{Endpoint: ovh.EndpointEU, ApplicationKey: "k"},
		{Endpoint: ovh.EndpointEU},
		{Endpoint: ovh.EndpointEU, ApplicationKey: "k", ApplicationSecret: "s", ConsumerKey: "c", ClientID: "id"},
		{Endpoint: "https://api.example.test/1.0", ClientID: "id", ClientSecret: "secret"},
	} {
		if _, err := ovh.New(&options); err == nil {
			t.Errorf("New(%+v) succeeded", options)
		}
	}
}
