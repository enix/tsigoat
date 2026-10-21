package ovh_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
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
// an update that fails before any request applied publishes nothing.
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

	// The first request fails, before it applies: nothing changes, and
	// nothing is refreshed.
	before, refreshes := api.Records(testZone), api.Refreshes()
	api.FailWrites(ovhtest.Failure{Status: http.StatusBadRequest, Message: "injected failure"})
	err := b.Apply(ctx, testZone, []backend.Change{replace(t, `www.example.test. 300 IN TXT "c"`)})
	if err == nil || backend.IsIndeterminate(err) || !strings.Contains(err.Error(), "injected failure") {
		t.Errorf("Apply() = %v, want the failure", err)
	}
	if !sameRecords(api.Records(testZone), before) || api.Refreshes() != refreshes {
		t.Errorf("after a failed update: records %v, %d refreshes", api.Records(testZone), api.Refreshes()-refreshes)
	}
}

// TestRecovery checks that an update whose request or refresh fails, after it
// applied or not, leaves the zone as it was, published, or tells that its
// outcome is unknown.
func TestRecovery(t *testing.T) {
	t.Parallel()
	pass := ovhtest.Failure{}
	committed := ovhtest.Failure{Status: http.StatusInternalServerError, Message: "lost response", AfterCommit: true}
	refused := ovhtest.Failure{Status: http.StatusInternalServerError, Message: "refused"}
	late := ovhtest.Failure{Late: true}
	for _, c := range []struct {
		label  string
		change string
		// op is the operation of the change, Replace when zero.
		op            backend.Op
		failures      []ovhtest.Failure
		indeterminate bool
		// canceled cancels the update while its requests run.
		canceled bool
	}{
		// Delete "old", create "new", which applies but fails.
		{label: "creation", change: `www.example.test. 300 IN TXT "new"`, failures: []ovhtest.Failure{pass, committed}},
		// Add "new" beside "old", which applies but fails.
		{label: "addition", change: `www.example.test. 300 IN TXT "new"`, op: backend.Add, failures: []ovhtest.Failure{committed}},
		// Remove "old", which applies but fails.
		{label: "removal", change: `www.example.test. 300 IN TXT "old"`, op: backend.Remove, failures: []ovhtest.Failure{committed}},
		// Delete "old", then create "new", which times out and applies
		// after the recovery: the records read again do not show it.
		{label: "late creation", change: `www.example.test. 300 IN TXT "new"`, indeterminate: true, failures: []ovhtest.Failure{pass, late}},
		// Add "new", which times out and applies after the recovery.
		{label: "late addition", change: `www.example.test. 300 IN TXT "new"`, op: backend.Add, indeterminate: true, failures: []ovhtest.Failure{late}},
		// Add "new", whose update is canceled while the request runs, which
		// applies after the recovery.
		{label: "canceled addition", change: `www.example.test. 300 IN TXT "new"`, op: backend.Add, indeterminate: true, canceled: true, failures: []ovhtest.Failure{late}},
		// Delete "old", which applies but fails.
		{label: "deletion", change: `www.example.test. 300 IN TXT "new"`, failures: []ovhtest.Failure{committed}},
		// Retime "old", which applies but fails.
		{label: "retime", change: `www.example.test. 600 IN TXT "old"`, failures: []ovhtest.Failure{committed}},
		// The three refreshes apply but fail; the refresh of the records
		// restored succeeds.
		{label: "refresh", change: `www.example.test. 300 IN TXT "new"`, failures: []ovhtest.Failure{
			pass, pass, committed, committed, committed,
		}},
		// The refresh of the records restored fails too: the name servers
		// may serve the update.
		{label: "refresh after restoring", change: `www.example.test. 300 IN TXT "new"`, indeterminate: true, failures: []ovhtest.Failure{
			pass, pass, committed, committed, committed, pass, pass, refused, refused, refused,
		}},
		// Restoring fails: the zone may hold part of the update.
		{label: "restoring", change: `www.example.test. 300 IN TXT "new"`, indeterminate: true, failures: []ovhtest.Failure{
			pass, committed, refused,
		}},
	} {
		t.Run(c.label, func(t *testing.T) {
			t.Parallel()
			api := ovhtest.New(t)
			api.CreateZone(testZone, rr(t, `www.example.test. 300 IN TXT "old"`))
			b, err := ovh.New(&ovh.Options{
				Endpoint:       api.URL,
				ApplicationKey: ovhtest.ApplicationKey, ApplicationSecret: ovhtest.ApplicationSecret, ConsumerKey: ovhtest.ConsumerKey,
				RefreshDelay: time.Millisecond, Timeout: 200 * time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			before := api.Records(testZone)
			api.FailWrites(c.failures...)
			change := replace(t, c.change)
			if c.op != 0 {
				change.Op = c.op
			}
			ctx := t.Context()
			if c.canceled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
			}
			err = b.Apply(ctx, testZone, []backend.Change{change})
			switch {
			case err == nil:
				t.Fatal("Apply() succeeded, want an error")
			case backend.IsIndeterminate(err) != c.indeterminate:
				t.Fatalf("Apply() = %v, want an indeterminate outcome: %t", err, c.indeterminate)
			case c.indeterminate:
				// A request that timed out applies now: the zone holds it,
				// which its next refresh publishes.
				if slices.Contains(c.failures, late) {
					api.Land()
					if !slices.ContainsFunc(api.Records(testZone), func(r ovhtest.Record) bool { return r.Target == `"new"` }) {
						t.Errorf("records %v, want the late record", api.Records(testZone))
					}
				}
				return
			}
			if !strings.Contains(err.Error(), "the records are as they were") {
				t.Errorf("Apply() = %v, want the records restored", err)
			}
			if !sameRecords(api.Records(testZone), before) || !sameRecords(api.Published(testZone), before) {
				t.Errorf("records %v, published %v, want %v", api.Records(testZone), api.Published(testZone), before)
			}
		})
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

// sameRecords reports whether two lists of records hold the same records,
// TTLs included, whatever their identifiers.
func sameRecords(a, b []ovhtest.Record) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[string]int{}
	for _, r := range a {
		count[fmt.Sprintf("%s %s %s %d", r.SubDomain, r.FieldType, r.Target, r.TTL)]++
	}
	for _, r := range b {
		count[fmt.Sprintf("%s %s %s %d", r.SubDomain, r.FieldType, r.Target, r.TTL)]--
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
