package backendtest

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
)

// ttl is the TTL of the records of the cases, above the minimum of every
// provider.
const ttl = 300

// recordsCase is a case that writes records at a name, reads them back, then
// deletes them.
type recordsCase struct {
	// label names the case.
	label string
	// name is the owner name of the records, relative to Base.
	name string
	// records are the records, as their type and RDATA in presentation
	// format, such as "MX 10 mail.example.net.".
	records []string
}

// txtCases returns the TXT contents that a backend must keep intact: their
// owner names are the label below "txt".
func txtCases() []recordsCase {
	long := strings.Repeat("a", 255)
	return []recordsCase{
		{label: "acme", records: []string{`TXT "pwv1DlMc4agXVh8vXVtmRdToBr7PWMzF6M9rgEWgkKg"`}},
		{label: "space", records: []string{`TXT "hello world"`}},
		{label: "padded", records: []string{`TXT " padded "`}},
		{label: "quote", records: []string{`TXT "say \"hi\""`}},
		{label: "backslash", records: []string{`TXT "back\\slash"`}},
		{label: "dkim", records: []string{`TXT "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="`}},
		{label: "utf8", records: []string{`TXT "caf\195\169"`}},
		{label: "strings", records: []string{`TXT "first" "second"`}},
		{label: "long", records: []string{`TXT "` + long + `" "` + strings.Repeat("b", 45) + `"`}},
		{label: "empty", records: []string{`TXT ""`}},
	}
}

// typeCases returns a sample of every record type that a backend may hold,
// at an owner name of its own. The DS record needs the NS records of a
// delegation beside it.
func typeCases() []recordsCase {
	const digest = "6c2a1b1d0f63b0f4a11b3ff5e93fc7f1c19f8f0e3c3a5a9c7a4b0b8a8f1e2d3c"
	return []recordsCase{
		{label: "A", name: "a.types", records: []string{"A 192.0.2.1", "A 192.0.2.2"}},
		{label: "AAAA", name: "aaaa.types", records: []string{"AAAA 2001:db8::1"}},
		{label: "CNAME", name: "cname.types", records: []string{"CNAME target.example.net."}},
		{label: "MX", name: "mx.types", records: []string{"MX 10 mail1.example.net.", "MX 20 mail2.example.net."}},
		{label: "SRV", name: "_sip._tcp.srv.types", records: []string{"SRV 10 60 5060 sip.example.net."}},
		{label: "CAA", name: "caa.types", records: []string{`CAA 0 issue "letsencrypt.org"`, `CAA 0 iodef "mailto:security@example.net"`}},
		{label: "NS", name: "ns.types", records: []string{"NS ns1.example.net.", "NS ns2.example.net."}},
		{label: "DS", name: "ds.types", records: []string{"NS ns1.example.net.", "DS 12345 13 2 " + digest}},
		{label: "PTR", name: "ptr.types", records: []string{"PTR host.example.net."}},
		{label: "SSHFP", name: "sshfp.types", records: []string{"SSHFP 4 2 " + digest}},
		{label: "TLSA", name: "_443._tcp.tlsa.types", records: []string{"TLSA 3 1 1 " + digest}},
		{label: "HTTPS", name: "https.types", records: []string{`HTTPS 1 . alpn="h2,h3"`}},
		{label: "SVCB", name: "svcb.types", records: []string{"SVCB 1 svc.example.net. port=8443"}},
		{label: "NAPTR", name: "naptr.types", records: []string{`NAPTR 100 10 "U" "E2U+sip" "!^.*$!sip:info@example.net!" .`}},
		{label: "NAPTR-backreference", name: "backreference.naptr.types", records: []string{`NAPTR 100 10 "U" "E2U+sip" "!^.*$!sip:\\1@example.net!" .`}},
		{label: "LOC", name: "loc.types", records: []string{"LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m"}},
		{label: "URI", name: "_http._tcp.uri.types", records: []string{`URI 10 1 "https://example.net/"`}},
		{label: "HINFO", name: "hinfo.types", records: []string{`HINFO "PC" "Linux"`}},
		{label: "RP", name: "rp.types", records: []string{"RP admin.example.net. info.example.net."}},
		{label: "DNAME", name: "dname.types", records: []string{"DNAME example.net."}},
	}
}

// roundTrip writes the records of a case, reads them back, then deletes them;
// then adds them, and removes them as they read back, as the engine does.
// For a case that the backend must turn down, it checks that it turns down
// both, without writing anything.
func (s *Suite) roundTrip(t *testing.T, label, relative string, records []string) {
	t.Helper()
	name := s.name(relative)
	sets := parse(t, name, ttl, records...)
	if s.rejects(t, label, replace(sets...)) {
		s.expect(t, name)
		s.rejects(t, label, add(sets...))
		s.expect(t, name)
		return
	}
	s.expect(t, name, sets...)

	deletions := make([]backend.Change, 0, len(sets))
	for _, set := range sets {
		deletions = append(deletions, backend.Change{Op: backend.Delete, RRset: backend.RRset{Name: name, Type: set.Type}})
	}
	s.apply(t, deletions...)
	s.expect(t, name)

	s.apply(t, add(sets...)...)
	s.expect(t, name, sets...)
	s.apply(t, remove(s.lookup(t, name)...)...)
	s.expect(t, name)
}

// rejects applies changes, which must apply, unless the case is listed in
// Rejected: then they must be turned down. It reports whether they were.
func (s *Suite) rejects(t *testing.T, label string, changes []backend.Change) bool {
	t.Helper()
	reason, rejected := s.Rejected[label]
	err := s.Backend.Apply(t.Context(), s.Zone, changes)
	switch rejection, ok := errors.AsType[*backend.RejectionError](err); {
	case rejected && ok:
		t.Logf("turned down as expected (%s): %v", reason, rejection)
		return true
	case rejected:
		t.Fatalf("Apply() = %v, want a rejection: %s", err, reason)
	case err != nil:
		t.Fatalf("Apply(%v): %v", changes, err)
	}
	return false
}

// parse parses records, as their type and RDATA, into RRsets of name with
// the given TTL, in the order of their types.
func parse(t *testing.T, name string, ttl uint32, records ...string) []backend.RRset {
	t.Helper()
	var sets []backend.RRset
	for _, text := range records {
		rr, err := dns.NewRR(name + " " + strconv.FormatUint(uint64(ttl), 10) + " IN " + text)
		if err != nil || rr == nil {
			t.Fatalf("parsing %q: %v", text, err)
		}
		// The engine hands over the records as a DNS message carries them.
		if rr, err = backend.Canonical(rr); err != nil {
			t.Fatalf("encoding %q: %v", text, err)
		}
		i := slices.IndexFunc(sets, func(set backend.RRset) bool { return set.Type == rr.Header().Rrtype })
		if i < 0 {
			sets = append(sets, backend.RRset{Name: name, Type: rr.Header().Rrtype, TTL: ttl})
			i = len(sets) - 1
		}
		sets[i].Records = append(sets[i].Records, rr)
	}
	return sets
}
