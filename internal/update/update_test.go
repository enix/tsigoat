package update_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend/memory"
	"github.com/enix/tsigoat/internal/update"
	"github.com/enix/tsigoat/internal/zone"
	"github.com/enix/tsigoat/test/scenario"
)

const testZone = "example.test."

// apex holds the records every test zone starts with.
func apex() []string {
	return []string{
		"@ 3600 IN SOA ns1 hostmaster 10 7200 900 1209600 300",
		"@ 3600 IN NS ns1",
	}
}

func newBackend(t *testing.T, records ...string) *memory.Backend {
	t.Helper()
	rrs, err := scenario.ParseRecords(append(apex(), records...), testZone)
	if err != nil {
		t.Fatal(err)
	}
	b := memory.New()
	b.SetZone(testZone, rrs...)
	return b
}

// process runs a request through the whole engine, as the server does once
// the request is authorised, and returns the rcode.
func process(t *testing.T, b *memory.Backend, request *scenario.Request, served ...string) int {
	t.Helper()
	messages, err := request.Messages(testZone)
	if err != nil {
		t.Fatal(err)
	}
	m := roundtrip(t, messages[0])

	zoneName, class, err := update.ParseZone(m)
	if err != nil {
		return rcodeOf(t, err)
	}
	req, err := update.Parse(m, zoneName, class, append(served, testZone))
	if err != nil {
		return rcodeOf(t, err)
	}
	view := zone.NewView(b, zoneName)
	if err := update.CheckPrerequisites(t.Context(), view, req); err != nil {
		return rcodeOf(t, err)
	}
	if err := update.Apply(t.Context(), view, req); err != nil {
		t.Fatal(err)
	}
	if err := b.Apply(t.Context(), zoneName, view.Changes()); err != nil {
		t.Fatal(err)
	}
	return dns.RcodeSuccess
}

// rcodeOf returns the rcode of a rejection, and fails on other errors.
func rcodeOf(t *testing.T, err error) int {
	t.Helper()
	rejected, ok := errors.AsType[*update.Error](err)
	if !ok {
		t.Fatal(err)
	}
	if rejected.Reason == "" {
		t.Errorf("rejection without a reason: %v", err)
	}
	return rejected.Rcode
}

// roundtrip packs and unpacks a message, so that the records carry their
// wire attributes such as RDLENGTH.
func roundtrip(t *testing.T, m *dns.Msg) *dns.Msg {
	t.Helper()
	data, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	out := new(dns.Msg)
	if err := out.Unpack(data); err != nil {
		t.Fatal(err)
	}
	return out
}

// contents returns the records of the test zone but the SOA and the apex NS,
// relative to the zone, one per line.
func contents(t *testing.T, b *memory.Backend) []string {
	t.Helper()
	records, err := b.Records(testZone)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, rr := range records {
		h := rr.Header()
		if h.Rrtype == dns.TypeSOA || (h.Rrtype == dns.TypeNS && h.Name == testZone) {
			continue
		}
		line := strings.Join(strings.Fields(rr.String()), " ")
		lines = append(lines, strings.Replace(line, "."+testZone, "", 1))
	}
	return lines
}

func TestEngine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		zone    []string
		request scenario.Request
		rcode   int
		want    []string
	}{
		// RFC 2136 3.2: prerequisites.
		{
			name:    "name in use holds",
			zone:    []string{"www 300 IN A 192.0.2.1"},
			request: scenario.Request{Prerequisites: []string{"yxdomain www"}, Updates: []string{`add www 60 IN TXT "ok"`}},
			want:    []string{"www 300 IN A 192.0.2.1", `www 60 IN TXT "ok"`},
		},
		{
			name:    "name in use fails",
			request: scenario.Request{Prerequisites: []string{"yxdomain www"}, Updates: []string{`add www 60 IN TXT "ok"`}},
			rcode:   dns.RcodeNameError,
		},
		{
			name:    "name not in use fails",
			zone:    []string{"www 300 IN A 192.0.2.1"},
			request: scenario.Request{Prerequisites: []string{"nxdomain www"}},
			rcode:   dns.RcodeYXDomain,
			want:    []string{"www 300 IN A 192.0.2.1"},
		},
		{
			name:    "empty non-terminal is not in use",
			zone:    []string{"a.b 300 IN A 192.0.2.1"},
			request: scenario.Request{Prerequisites: []string{"nxdomain b"}, Updates: []string{`add b 60 IN TXT "now"`}},
			want:    []string{"a.b 300 IN A 192.0.2.1", `b 60 IN TXT "now"`},
		},
		{
			name:    "RRset exists fails",
			zone:    []string{"www 300 IN A 192.0.2.1"},
			request: scenario.Request{Prerequisites: []string{"yxrrset www AAAA"}},
			rcode:   dns.RcodeNXRrset,
			want:    []string{"www 300 IN A 192.0.2.1"},
		},
		{
			name:    "RRset does not exist fails",
			zone:    []string{"www 300 IN A 192.0.2.1"},
			request: scenario.Request{Prerequisites: []string{"nxrrset www A"}},
			rcode:   dns.RcodeYXRrset,
			want:    []string{"www 300 IN A 192.0.2.1"},
		},
		{
			name: "value-dependent prerequisite holds in any order and case",
			zone: []string{"www 300 IN A 192.0.2.1", "www 300 IN A 192.0.2.2"},
			request: scenario.Request{
				UpperCaseNames: true,
				Prerequisites:  []string{"yxrrset www A 192.0.2.2", "yxrrset www A 192.0.2.1"},
				Updates:        []string{`add www 60 IN TXT "ok"`},
			},
			want: []string{"www 300 IN A 192.0.2.1", "www 300 IN A 192.0.2.2", `www 60 IN TXT "ok"`},
		},
		{
			name:    "value-dependent prerequisite naming part of the RRset fails",
			zone:    []string{"www 300 IN A 192.0.2.1", "www 300 IN A 192.0.2.2"},
			request: scenario.Request{Prerequisites: []string{"yxrrset www A 192.0.2.1"}},
			rcode:   dns.RcodeNXRrset,
			want:    []string{"www 300 IN A 192.0.2.1", "www 300 IN A 192.0.2.2"},
		},
		{
			name:    "prerequisite with a TTL",
			request: scenario.Request{Prerequisites: []string{"raw www 300 IN A 192.0.2.1"}},
			rcode:   dns.RcodeFormatError,
		},
		{
			name:    "prerequisite outside the zone",
			request: scenario.Request{Prerequisites: []string{"yxdomain www.elsewhere.test."}},
			rcode:   dns.RcodeNotZone,
		},
		// RFC 2136 3.4.1: prescan.
		{
			name:    "update outside the zone",
			request: scenario.Request{Updates: []string{`add www.elsewhere.test. 60 IN TXT "no"`}},
			rcode:   dns.RcodeNotZone,
		},
		{
			name:    "update in a more specific served zone",
			request: scenario.Request{Updates: []string{`add www.sub 60 IN TXT "no"`}},
			rcode:   dns.RcodeNotZone,
		},
		{
			name:    "class ANY with a TTL",
			request: scenario.Request{Updates: []string{"rawheader www 60 ANY A"}},
			rcode:   dns.RcodeFormatError,
		},
		{
			name:    "add of type ANY",
			request: scenario.Request{Updates: []string{"rawheader www 60 IN ANY"}},
			rcode:   dns.RcodeFormatError,
		},
		{
			name:    "add of a meta type",
			request: scenario.Request{Updates: []string{"rawheader www 60 IN AXFR"}},
			rcode:   dns.RcodeFormatError,
		},
		// RFC 2136 3.4.2.2: additions.
		{
			name:    "add sets the TTL of the RRset",
			zone:    []string{`www 3600 IN TXT "one"`},
			request: scenario.Request{Updates: []string{`add www 60 IN TXT "two"`}},
			want:    []string{`www 60 IN TXT "one"`, `www 60 IN TXT "two"`},
		},
		{
			name:    "add of a duplicate replaces it",
			zone:    []string{`www 3600 IN TXT "one"`},
			request: scenario.Request{Updates: []string{`add WWW 60 IN TXT "one"`}},
			want:    []string{`www 60 IN TXT "one"`},
		},
		{
			name:    "CNAME beside data is ignored",
			zone:    []string{"www 300 IN A 192.0.2.1"},
			request: scenario.Request{Updates: []string{"add www 300 IN CNAME target.example."}},
			want:    []string{"www 300 IN A 192.0.2.1"},
		},
		{
			name:    "data beside a CNAME is ignored",
			zone:    []string{"www 300 IN CNAME target.example."},
			request: scenario.Request{Updates: []string{`add www 60 IN TXT "no"`}},
			want:    []string{"www 300 IN CNAME target.example."},
		},
		{
			name:    "CNAME replaces a CNAME",
			zone:    []string{"www 300 IN CNAME one.example."},
			request: scenario.Request{Updates: []string{"add www 60 IN CNAME two.example."}},
			want:    []string{"www 60 IN CNAME two.example."},
		},
		{
			name:    "RRSIG beside a CNAME is accepted",
			zone:    []string{"www 300 IN CNAME target.example."},
			request: scenario.Request{Updates: []string{"add www 300 IN NSEC next.example.test. CNAME RRSIG NSEC"}},
			want:    []string{"www 300 IN CNAME target.example.", "www 300 IN NSEC next.example.test. CNAME RRSIG NSEC"},
		},
		{
			name:    "SOA with a greater serial replaces the SOA",
			request: scenario.Request{Updates: []string{"add @ 3600 IN SOA ns1 hostmaster 11 7200 900 1209600 300"}},
		},
		// RFC 2136 3.4.2.3: RRset deletions.
		{
			name:    "delete an RRset",
			zone:    []string{`www 60 IN TXT "one"`, "www 300 IN A 192.0.2.1"},
			request: scenario.Request{Updates: []string{"delete www TXT"}},
			want:    []string{"www 300 IN A 192.0.2.1"},
		},
		{
			name:    "delete every RRset of a delegation",
			zone:    []string{"sub2 3600 IN NS ns.elsewhere.test.", `sub2 60 IN TXT "x"`},
			request: scenario.Request{Updates: []string{"delete sub2"}},
		},
		{
			name:    "delete every RRset of the apex keeps SOA and NS",
			zone:    []string{`@ 60 IN TXT "apex"`},
			request: scenario.Request{Updates: []string{"delete @"}},
		},
		{
			name:    "delete the apex NS RRset is ignored, whatever the case",
			request: scenario.Request{UpperCaseNames: true, Updates: []string{"delete @ NS", "delete @ SOA"}},
		},
		// RFC 2136 3.4.2.4: record deletions.
		{
			name:    "delete a record",
			zone:    []string{`www 60 IN TXT "one"`, `www 60 IN TXT "two"`},
			request: scenario.Request{Updates: []string{`delete WWW TXT "one"`}},
			want:    []string{`www 60 IN TXT "two"`},
		},
		{
			name:    "delete a record written with escapes",
			zone:    []string{`www 60 IN TXT "a\032b"`, `www 60 IN TXT "\195\169t\195\169"`},
			request: scenario.Request{Updates: []string{`delete www TXT "a b"`, `delete www TXT "été"`}},
		},
		{
			name:    "value-dependent prerequisite on a record written with escapes",
			zone:    []string{`www 60 IN TXT "a\032b"`},
			request: scenario.Request{Prerequisites: []string{`yxrrset www TXT "a b"`}, Updates: []string{`add www 60 IN TXT "c"`}},
			want:    []string{`www 60 IN TXT "a b"`, `www 60 IN TXT "c"`},
		},
		{
			name:    "delete the last apex NS is ignored",
			request: scenario.Request{Updates: []string{"delete @ NS ns1"}},
		},
		{
			name:    "delete one of two apex NS",
			zone:    []string{"@ 3600 IN NS ns2"},
			request: scenario.Request{Updates: []string{"delete @ NS ns2"}},
		},
		{
			name:    "delete the last NS of a delegation",
			zone:    []string{"sub2 3600 IN NS ns.elsewhere.test."},
			request: scenario.Request{Updates: []string{"delete sub2 NS ns.elsewhere.test."}},
		},
		{
			name:    "updates apply in order",
			request: scenario.Request{Updates: []string{`add www 60 IN TXT "a"`, `delete www TXT "a"`, `add www 60 IN TXT "b"`}},
			want:    []string{`www 60 IN TXT "b"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			b := newBackend(t, tt.zone...)
			before := contents(t, b)
			rcode := process(t, b, &tt.request, "sub.example.test.")
			if rcode != tt.rcode {
				t.Errorf("rcode %s, want %s", dns.RcodeToString[rcode], dns.RcodeToString[tt.rcode])
			}

			want := tt.want
			if tt.rcode != dns.RcodeSuccess {
				want = before
			}
			got := contents(t, b)
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("zone content:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}

			if countApexNS(t, b) == 0 {
				t.Error("the apex lost its NS records")
			}
		})
	}
}

func countApexNS(t *testing.T, b *memory.Backend) int {
	t.Helper()
	records, err := b.Records(testZone)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, rr := range records {
		if rr.Header().Rrtype == dns.TypeNS && rr.Header().Name == testZone {
			count++
		}
	}
	return count
}

func TestSOASerial(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		serial uint32
		want   uint32
	}{
		{serial: 11, want: 11},
		{serial: 9, want: 10},
		{serial: 10, want: 10},
		{serial: 10 + 1<<31 + 1, want: 10},
	} {
		b := newBackend(t)
		request := scenario.Request{Updates: []string{
			"add @ 3600 IN SOA ns1 hostmaster " + strconv.FormatUint(uint64(tt.serial), 10) + " 7200 900 1209600 300",
		}}
		if rcode := process(t, b, &request); rcode != dns.RcodeSuccess {
			t.Fatalf("rcode %s", dns.RcodeToString[rcode])
		}
		records, err := b.Records(testZone)
		if err != nil {
			t.Fatal(err)
		}
		for _, rr := range records {
			if soa, ok := rr.(*dns.SOA); ok && soa.Serial != tt.want {
				t.Errorf("serial %d after adding %d, want %d", soa.Serial, tt.serial, tt.want)
			}
		}
	}
}

func TestParseZone(t *testing.T) {
	t.Parallel()

	m := new(dns.Msg)
	m.SetUpdate("Example.TEST")
	zoneName, class, err := update.ParseZone(m)
	if zoneName != testZone || class != dns.ClassINET || err != nil {
		t.Errorf("ParseZone() = %q, %d, %v", zoneName, class, err)
	}

	for _, class := range []uint16{dns.ClassANY, dns.ClassNONE} {
		m.Question[0].Qclass = class
		if _, _, err := update.ParseZone(m); rcodeOf(t, err) != dns.RcodeFormatError {
			t.Errorf("zone class %s: %v, want FORMERR", dns.ClassToString[class], err)
		}
	}
	m.Question[0].Qclass = dns.ClassINET

	m.Question[0].Qtype = dns.TypeA
	if _, _, err := update.ParseZone(m); rcodeOf(t, err) != dns.RcodeFormatError {
		t.Errorf("zone type A: %v, want FORMERR", err)
	}
	m.Question[0].Qtype = dns.TypeSOA

	m.Question = append(m.Question, m.Question[0])
	if _, _, err := update.ParseZone(m); rcodeOf(t, err) != dns.RcodeFormatError {
		t.Errorf("two zone entries: %v, want FORMERR", err)
	}
	m.Question = nil
	if _, _, err := update.ParseZone(m); rcodeOf(t, err) != dns.RcodeFormatError {
		t.Errorf("no zone entry: %v, want FORMERR", err)
	}
}

func TestZoneOf(t *testing.T) {
	t.Parallel()

	served := []string{"example.test.", "sub.example.test.", "other.test."}
	for name, want := range map[string]string{
		"example.test.":           "example.test.",
		"WWW.Example.Test":        "example.test.",
		"www.sub.example.test.":   "sub.example.test.",
		"sub.example.test.":       "sub.example.test.",
		"subway.example.test.":    "example.test.",
		"test.":                   "",
		"www.elsewhere.test.":     "",
		"www.other.test.":         "other.test.",
		"other.test.example.test": "example.test.",
	} {
		if got := update.ZoneOf(name, served); got != want {
			t.Errorf("ZoneOf(%q) = %q, want %q", name, got, want)
		}
	}
	if got := update.ZoneOf("www.example.test.", []string{"."}); got != "." {
		t.Errorf("ZoneOf() under the root zone = %q", got)
	}
}

func TestParseTooManyRecords(t *testing.T) {
	t.Parallel()

	updates := make([]string, update.MaxRecords+1)
	for i := range updates {
		updates[i] = `add www 60 IN TXT "x"`
	}
	b := newBackend(t)
	if rcode := process(t, b, &scenario.Request{Updates: updates}); rcode != dns.RcodeRefused {
		t.Errorf("rcode %s, want REFUSED", dns.RcodeToString[rcode])
	}
}

// FuzzEngine feeds arbitrary messages to the engine: it must never panic,
// and must leave the zone with its SOA and apex NS.
func FuzzEngine(f *testing.F) {
	for _, request := range []*scenario.Request{
		{Updates: []string{`add www 60 IN TXT "x"`}},
		{Prerequisites: []string{"nxdomain www", "yxrrset @ NS"}, Updates: []string{"delete @", "delete www A 192.0.2.1"}},
		{Updates: []string{"add @ 3600 IN SOA ns1 hostmaster 11 7200 900 1209600 300", "add www 60 IN CNAME x."}},
	} {
		messages, err := request.Messages(testZone)
		if err != nil {
			f.Fatal(err)
		}
		data, err := messages[0].Pack()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		m := new(dns.Msg)
		if err := m.Unpack(data); err != nil {
			return
		}
		zoneName, class, err := update.ParseZone(m)
		if err != nil || zoneName != testZone {
			return
		}
		req, err := update.Parse(m, zoneName, class, []string{testZone})
		if err != nil {
			return
		}
		b := newBackend(t)
		view := zone.NewView(b, zoneName)
		if err := update.CheckPrerequisites(t.Context(), view, req); err != nil {
			return
		}
		if err := update.Apply(t.Context(), view, req); err != nil {
			return
		}
		if err := b.Apply(t.Context(), zoneName, view.Changes()); err != nil {
			return
		}
		if countApexNS(t, b) == 0 {
			t.Fatal("the apex lost its NS records")
		}
	})
}
