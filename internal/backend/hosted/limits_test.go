package hosted_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/hosted"
)

func TestCheck(t *testing.T) {
	t.Parallel()
	const zone = "example.test."
	limits := &hosted.Limits{
		Provider: "Provider",
		Types:    []uint16{dns.TypeA, dns.TypeTXT, dns.TypeNS},
		MinTTL:   60,
		MaxTTL:   86400,
		Content: func(rr dns.RR) string {
			if txt, ok := rr.(*dns.TXT); ok && len(txt.Txt) > 1 {
				return "one string only"
			}
			return ""
		},
	}
	replace := func(text string) backend.Change {
		record := rr(t, text)
		h := record.Header()
		return backend.Change{Op: backend.Replace, RRset: backend.RRset{Name: dns.CanonicalName(h.Name), Type: h.Rrtype, TTL: h.Ttl, Records: []dns.RR{record}}}
	}
	remove := func(name string, rrtype uint16) backend.Change {
		return backend.Change{Op: backend.Delete, RRset: backend.RRset{Name: name, Type: rrtype}}
	}
	for _, c := range []struct {
		label  string
		change backend.Change
		reason string
	}{
		{label: "fine", change: replace(`www.example.test. 300 IN TXT "a"`)},
		{label: "wildcard", change: replace("*.example.test. 300 IN A 192.0.2.1")},
		{label: "underscore", change: replace(`_acme-challenge.example.test. 60 IN TXT "a"`)},
		{label: "apex", change: replace(`example.test. 300 IN TXT "a"`)},
		{label: "delegation", change: replace("sub.example.test. 300 IN NS ns.example.net.")},
		{label: "soa", change: replace("example.test. 300 IN SOA ns. host. 2 1 1 1 1"), reason: "Provider manages the SOA record"},
		{label: "apex ns", change: replace("example.test. 300 IN NS ns.example.net."), reason: "Provider manages the NS records of the apex"},
		{label: "type", change: replace("www.example.test. 300 IN AAAA 2001:db8::1"), reason: "Provider holds no AAAA record"},
		{label: "low ttl", change: replace("www.example.test. 59 IN A 192.0.2.1"), reason: "Provider holds no TTL below 60"},
		{label: "high ttl", change: replace("www.example.test. 86401 IN A 192.0.2.1"), reason: "Provider holds no TTL above 86400"},
		{label: "inner wildcard", change: replace("a.*.example.test. 300 IN A 192.0.2.1"), reason: "holds no name like a.*.example.test."},
		{label: "escaped dot", change: replace(`a\.b.example.test. 300 IN A 192.0.2.1`), reason: "holds no name like"},
		{label: "space", change: replace(`a\032b.example.test. 300 IN A 192.0.2.1`), reason: "holds no name like"},
		{label: "content", change: replace(`www.example.test. 300 IN TXT "a" "b"`), reason: `Provider holds no TXT record like "a" "b": one string only`},
		{label: "delete of another type", change: remove("www.example.test.", dns.TypeAAAA)},
		{label: "delete of apex ns", change: remove(zone, dns.TypeNS), reason: "manages the NS records of the apex"},
	} {
		err := limits.Check(zone, []backend.Change{replace(`ok.example.test. 300 IN TXT "ok"`), c.change})
		rejection, rejected := errors.AsType[*backend.RejectionError](err)
		switch {
		case c.reason == "" && err != nil:
			t.Errorf("%s: Check() = %v, want no rejection", c.label, err)
		case c.reason != "" && (!rejected || rejection.Rcode != dns.RcodeRefused || !strings.Contains(rejection.Reason, c.reason)):
			t.Errorf("%s: Check() = %v, want REFUSED: %s", c.label, err, c.reason)
		}
	}
}

func TestRelative(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{
		"example.test.":                 "",
		"www.example.test.":             "www",
		"_acme-challenge.example.test.": "_acme-challenge",
		"a.b.example.test.":             "a.b",
	} {
		if got := hosted.Relative(name, "example.test."); got != want {
			t.Errorf("Relative(%s) = %q, want %q", name, got, want)
		}
	}
}
