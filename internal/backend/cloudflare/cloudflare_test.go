package cloudflare_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/cloudflare"
	"github.com/enix/tsigoat/internal/backend/cloudflare/cloudflaretest"
)

func rr(t *testing.T, text string) dns.RR {
	t.Helper()
	parsed, err := dns.NewRR(text)
	if err != nil || parsed == nil {
		t.Fatalf("parsing %q: %v", text, err)
	}
	return parsed
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

func TestToAPI(t *testing.T) {
	t.Parallel()
	for text, want := range map[string]string{
		"www.example.test. 300 IN A 192.0.2.1":                                       `{"name":"www.example.test","type":"A","content":"192.0.2.1","ttl":300}`,
		"www.example.test. 300 IN AAAA 2001:db8:0::1":                                `{"name":"www.example.test","type":"AAAA","content":"2001:db8::1","ttl":300}`,
		"Www.example.test. 60 IN CNAME Target.example.net.":                          `{"name":"www.example.test","type":"CNAME","content":"Target.example.net","ttl":60}`,
		"example.test. 300 IN MX 10 mail.example.net.":                               `{"name":"example.test","type":"MX","content":"mail.example.net","priority":10,"ttl":300}`,
		"example.test. 300 IN MX 0 .":                                                `{"name":"example.test","type":"MX","content":".","priority":0,"ttl":300}`,
		`www.example.test. 300 IN TXT "a \"b\"" "c"`:                                 `{"name":"www.example.test","type":"TXT","content":"\"a \\\"b\\\"\" \"c\"","ttl":300}`,
		"_sip._tcp.example.test. 300 IN SRV 10 60 5060 sip.test.":                    `{"name":"_sip._tcp.example.test","type":"SRV","data":{"priority":10,"weight":60,"port":5060,"target":"sip.test"},"ttl":300}`,
		`example.test. 300 IN CAA 0 issue "letsencrypt.org"`:                         `{"name":"example.test","type":"CAA","data":{"flags":0,"tag":"issue","value":"letsencrypt.org"},"ttl":300}`,
		`example.test. 300 IN HTTPS 1 . alpn="h2,h3" port=443`:                       `{"name":"example.test","type":"HTTPS","data":{"priority":1,"target":".","value":"alpn=\"h2,h3\" port=\"443\""},"ttl":300}`,
		`_http._tcp.example.test. 300 IN URI 10 1 "https://x/"`:                      `{"name":"_http._tcp.example.test","type":"URI","data":{"weight":1,"target":"https://x/"},"priority":10,"ttl":300}`,
		"example.test. 300 IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 1m 10000m 10m": `{"name":"example.test","type":"LOC","data":{"lat_degrees":52,"lat_minutes":22,"lat_seconds":23,"lat_direction":"N","long_degrees":4,"long_minutes":53,"long_seconds":32,"long_direction":"E","altitude":-2,"size":1,"precision_horz":10000,"precision_vert":10},"ttl":300}`,
	} {
		record, err := cloudflare.ToAPI(rr(t, text))
		if err != nil {
			t.Errorf("ToAPI(%s): %v", text, err)
			continue
		}
		got, _ := json.Marshal(record)
		if string(got) != want {
			t.Errorf("ToAPI(%s) =\n%s\nwant\n%s", text, got, want)
		}
	}
	if _, err := cloudflare.ToAPI(rr(t, `www.example.test. 300 IN HINFO "PC" "Linux"`)); err == nil {
		t.Error("ToAPI() converted an HINFO record")
	}
}

func TestFromAPI(t *testing.T) {
	t.Parallel()
	priority := uint16(10)
	for _, c := range []struct {
		record cloudflare.APIRecord
		want   string
		locked bool
	}{
		{record: cloudflare.APIRecord{Name: "www.example.test", Type: "A", Content: "192.0.2.1", TTL: 1}, want: "www.example.test.\t300\tIN\tA\t192.0.2.1"},
		{record: cloudflare.APIRecord{Name: "www.example.test", Type: "CNAME", Content: "target.example.net", TTL: 60}, want: "www.example.test.\t60\tIN\tCNAME\ttarget.example.net."},
		{record: cloudflare.APIRecord{Name: "example.test", Type: "MX", Content: "mail.example.net", Priority: &priority, TTL: 300}, want: "example.test.\t300\tIN\tMX\t10 mail.example.net."},
		{record: cloudflare.APIRecord{Name: "www.example.test", Type: "TXT", Content: `"a \"b\"" "c"`, TTL: 300}, want: "www.example.test.\t300\tIN\tTXT\t\"a \\\"b\\\"\" \"c\""},
		{record: cloudflare.APIRecord{Name: "www.example.test", Type: "TXT", Content: `legacy "unquoted" content`, TTL: 300}, want: "www.example.test.\t300\tIN\tTXT\t\"legacy \\\"unquoted\\\" content\""},
		{
			record: cloudflare.APIRecord{
				Name: "_sip._tcp.example.test", Type: "SRV", Content: "60 5060 sip.test", Priority: &priority,
				Data: json.RawMessage(`{"priority":10,"weight":60,"port":5060,"target":"sip.test"}`), TTL: 300,
			},
			want: "_sip._tcp.example.test.\t300\tIN\tSRV\t10 60 5060 sip.test.",
		},
		{record: cloudflare.APIRecord{Name: "_443._tcp.example.test", Type: "TLSA", Content: "3 1 1 AB CD", TTL: 300}, want: "_443._tcp.example.test.\t300\tIN\tTLSA\t3 1 1 abcd"},
		{record: cloudflare.APIRecord{Name: "example.test", Type: "LOC", Content: "42 21 54.000 N 71 6 18.000 W -24.05 30.00 0.00 0.00", TTL: 300}, want: "example.test.\t300\tIN\tLOC\t42 21 54.000 N 71 06 18.000 W -24.05m 30m 0.00m 0.00m"},
		{record: cloudflare.APIRecord{Name: "www.example.test", Type: "A", Content: "192.0.2.1", TTL: 1, Proxied: true}, want: "www.example.test.\t300\tIN\tA\t192.0.2.1", locked: true},
		{record: cloudflare.APIRecord{Name: "www.example.test", Type: "ALIAS", Content: "x", TTL: 300}},
	} {
		held, err := cloudflare.FromAPI(&c.record)
		if err != nil {
			t.Errorf("FromAPI(%+v): %v", c.record, err)
			continue
		}
		got := ""
		if held.RR != nil {
			got = held.RR.String()
		}
		if got != c.want || (held.Locked != "") != c.locked {
			t.Errorf("FromAPI(%+v) = %q, locked %q; want %q, locked %t", c.record, got, held.Locked, c.want, c.locked)
		}
	}
}

func TestLookupApex(t *testing.T) {
	t.Parallel()
	b, _, _ := newBackend(t)
	sets, err := b.Lookup(t.Context(), testZone, testZone)
	if err != nil {
		t.Fatal(err)
	}
	var soa, ns int
	for _, set := range sets {
		switch set.Type {
		case dns.TypeSOA:
			soa = len(set.Records)
			if record, ok := set.Records[0].(*dns.SOA); !ok || record.Ns != "ns1.example.test." {
				t.Errorf("SOA = %s, want the first name server as primary", set.Records[0])
			}
		case dns.TypeNS:
			ns = len(set.Records)
		}
	}
	if soa != 1 || ns != 2 {
		t.Errorf("Lookup() of the apex = %v, want an SOA and the two name servers", sets)
	}
}

func TestZones(t *testing.T) {
	t.Parallel()
	api := cloudflaretest.New(t)
	id := api.CreateZone(testZone, "ns1.example.test.")

	// A zone that the token does not see.
	b, err := cloudflare.New(&cloudflare.Options{URL: api.URL, APIToken: cloudflaretest.Token})
	if err != nil {
		t.Fatal(err)
	}
	if _, lookupErr := b.Lookup(t.Context(), "other.test.", "other.test."); !errors.Is(lookupErr, backend.ErrZoneNotFound) {
		t.Errorf("Lookup() of an unknown zone = %v, want ErrZoneNotFound", lookupErr)
	}

	// A configured identifier saves the search.
	b, err = cloudflare.New(&cloudflare.Options{URL: api.URL, APIToken: cloudflaretest.Token, ZoneIDs: map[string]string{testZone: id}})
	if err != nil {
		t.Fatal(err)
	}
	before := api.Requests()
	for range 2 {
		if _, lookupErr := b.Lookup(t.Context(), testZone, "www."+testZone); lookupErr != nil {
			t.Fatal(lookupErr)
		}
	}
	if got := api.Requests() - before; got != 3 {
		t.Errorf("two lookups took %d requests, want the zone once and the records twice", got)
	}

	// A wrong token.
	b, err = cloudflare.New(&cloudflare.Options{URL: api.URL, APIToken: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Lookup(t.Context(), testZone, testZone); err == nil || !strings.Contains(err.Error(), "Authentication error [10000]") {
		t.Errorf("Lookup() with a wrong token = %v", err)
	}
}

func TestProxiedRecords(t *testing.T) {
	t.Parallel()
	b, api, id := newBackend(t)
	ctx := t.Context()
	if err := b.Apply(ctx, testZone, []backend.Change{
		replace(t, "www.example.test. 300 IN A 192.0.2.1"),
		replace(t, `www.example.test. 300 IN TXT "hello"`),
	}); err != nil {
		t.Fatal(err)
	}
	api.SetProxied(id, "www.example.test.", true)

	sets, err := b.Lookup(ctx, testZone, "www."+testZone)
	if err != nil || len(sets) != 2 {
		t.Fatalf("Lookup() = %v, %v, want the proxied A record and the TXT record", sets, err)
	}
	for _, change := range []backend.Change{
		replace(t, "www.example.test. 300 IN A 192.0.2.2"),
		{Op: backend.Delete, RRset: backend.RRset{Name: "www." + testZone, Type: dns.TypeA}},
		replace(t, "www.example.test. 300 IN AAAA 2001:db8::1"),
	} {
		err := b.Apply(ctx, testZone, []backend.Change{change})
		if rejection, ok := errors.AsType[*backend.RejectionError](err); !ok || !strings.Contains(rejection.Reason, "proxies") {
			t.Errorf("Apply(%s) = %v, want a rejection", change, err)
		}
	}
	if err := b.Apply(ctx, testZone, []backend.Change{replace(t, `www.example.test. 300 IN TXT "other"`)}); err != nil {
		t.Errorf("Apply() of the TXT record beside the proxied one: %v", err)
	}
}

func TestStaleState(t *testing.T) {
	t.Parallel()
	b, api, _ := newBackend(t)
	api.FailBatch(http.StatusBadRequest, 81058, "An identical record already exists.")
	if err := b.Apply(t.Context(), testZone, []backend.Change{replace(t, `www.example.test. 300 IN TXT "a"`)}); err != nil {
		t.Fatalf("Apply() after a stale state = %v, want a success on the second batch", err)
	}

	api.FailBatch(http.StatusBadRequest, 81058, "An identical record already exists.")
	api.FailBatch(http.StatusBadRequest, 81058, "An identical record already exists.")
	err := b.Apply(t.Context(), testZone, []backend.Change{replace(t, `www.example.test. 300 IN TXT "b"`)})
	if err == nil || !strings.Contains(err.Error(), "81058") {
		t.Errorf("Apply() = %v, want the error of the second batch", err)
	}
}

func TestAmbiguousOutcome(t *testing.T) {
	t.Parallel()
	b, api, _ := newBackend(t)
	// The batch applies, but the connection drops before the response.
	api.FailBatch(0, 0, "")
	if err := b.Apply(t.Context(), testZone, []backend.Change{replace(t, `www.example.test. 300 IN TXT "a"`)}); err != nil {
		t.Errorf("Apply() = %v, want a success read back", err)
	}
	// The server fails without applying.
	api.FailBatch(http.StatusInternalServerError, 1000, "Internal error")
	err := b.Apply(t.Context(), testZone, []backend.Change{replace(t, `www.example.test. 300 IN TXT "b"`)})
	if !backend.IsIndeterminate(err) || !strings.Contains(err.Error(), "do not show the update") {
		t.Errorf("Apply() = %v, want an unknown outcome, read back", err)
	}
}

func TestLargeUpdate(t *testing.T) {
	t.Parallel()
	b, _, _ := newBackend(t)
	lines := make([]string, 0, 201)
	for i := range 201 {
		lines = append(lines, fmt.Sprintf(`www.example.test. 300 IN TXT "%d"`, i))
	}
	err := b.Apply(t.Context(), testZone, []backend.Change{replace(t, lines...)})
	if rejection, ok := errors.AsType[*backend.RejectionError](err); !ok || !strings.Contains(rejection.Reason, "201 operations") {
		t.Errorf("Apply() = %v, want a rejection", err)
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	for _, options := range []cloudflare.Options{
		{APIToken: ""},
		{APIToken: "token", URL: "ftp://example.test"},
	} {
		if _, err := cloudflare.New(&options); err == nil {
			t.Errorf("New(%+v) succeeded", options)
		}
	}
}

// TestRoundTrip checks that the records whose strings hold escapes come back
// from the simulated API as they went, as the API takes their fields raw and
// renders their content in presentation format.
func TestRoundTrip(t *testing.T) {
	t.Parallel()
	b, _, _ := newBackend(t)
	for _, text := range []string{
		`naptr.example.test. 300 IN NAPTR 100 10 "U" "E2U+sip" "!^.*$!sip:\\1@example.net!" .`,
		`quotes.example.test. 300 IN NAPTR 100 10 "U" "E2U+sip" "!^(.*)$!sip:\"q\"@example.net!" .`,
		`caa.example.test. 300 IN CAA 0 iodef "mailto:a\"b@example.net"`,
		`caa2.example.test. 300 IN CAA 0 issue "letsencrypt.org; validationmethods=dns-01"`,
		`_http._tcp.example.test. 300 IN URI 10 1 "https://example.net/a\"b"`,
		`https.example.test. 300 IN HTTPS 1 . alpn="h2\;foo"`,
		`svcb.example.test. 300 IN SVCB 1 svc.example.net. alpn="h2,h3" port="8443"`,
		`txt.example.test. 300 IN TXT "back\\slash" "say \"hi\""`,
	} {
		change := replace(t, text)
		if err := b.Apply(t.Context(), testZone, []backend.Change{change}); err != nil {
			t.Errorf("Apply(%s): %v", text, err)
			continue
		}
		sets, err := b.Lookup(t.Context(), testZone, change.RRset.Name)
		if err != nil || len(sets) != 1 || len(sets[0].Records) != 1 {
			t.Errorf("Lookup(%s) = %v, %v", change.RRset.Name, sets, err)
			continue
		}
		want, err := backend.Canonical(change.RRset.Records[0])
		if err != nil {
			t.Fatal(err)
		}
		if got := sets[0].Records[0]; !dns.IsDuplicate(got, want) {
			t.Errorf("%s came back as %s", want, got)
		}
	}
	for _, text := range []string{
		`naptr.example.test. 300 IN NAPTR 100 10 "U" "E2U+sip" "!^.*$!caf\195\169!" .`,
		`txt.example.test. 300 IN TXT "caf\195\169"`,
	} {
		err := b.Apply(t.Context(), testZone, []backend.Change{replace(t, text)})
		if _, ok := errors.AsType[*backend.RejectionError](err); !ok {
			t.Errorf("Apply(%s) = %v, want a rejection of the bytes outside printable ASCII", text, err)
		}
	}
}
