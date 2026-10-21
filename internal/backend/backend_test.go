package backend_test

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
)

func TestRData(t *testing.T) {
	t.Parallel()

	for text, want := range map[string]string{
		"www.example.test. 60 IN A 192.0.2.1":                       "192.0.2.1",
		`www.example.test. 60 IN TXT "a b" "c\"d"`:                  `"a b" "c\"d"`,
		"www.example.test. 60 IN MX 10 mail.example.test.":          "10 mail.example.test.",
		`example.test. 60 IN CAA 0 issue "letsencrypt.org"`:         `0 issue "letsencrypt.org"`,
		`www.example.test. 60 IN TYPE65534 \# 4 0a000001`:           `\# 4 0a000001`,
		"example.test. 60 IN SOA ns1. host. 1 7200 900 1209600 300": "ns1. host. 1 7200 900 1209600 300",
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		if got := backend.RData(rr); got != want {
			t.Errorf("RData(%s) = %q, want %q", text, got, want)
		}
	}
}

func TestChangeString(t *testing.T) {
	t.Parallel()

	a, err := dns.NewRR(`www.example.test. 60 IN TXT "a"`)
	if err != nil {
		t.Fatal(err)
	}
	b, err := dns.NewRR(`www.example.test. 60 IN TXT "b"`)
	if err != nil {
		t.Fatal(err)
	}
	for change, want := range map[*backend.Change]string{
		{Op: backend.Replace, RRset: backend.RRset{Name: "www.example.test.", Type: dns.TypeTXT, TTL: 60, Records: []dns.RR{a, b}}}: `replace www.example.test. TXT 60 ["a", "b"]`,
		{Op: backend.Delete, RRset: backend.RRset{Name: "www.example.test.", Type: dns.TypeA}}:                                      "delete www.example.test. A",
		{Op: backend.Add, RRset: backend.RRset{Name: "www.example.test.", Type: dns.TypeTXT, TTL: 60, Records: []dns.RR{a}}}:        `add www.example.test. TXT 60 ["a"]`,
		{Op: backend.Remove, RRset: backend.RRset{Name: "www.example.test.", Type: dns.TypeTXT, Records: []dns.RR{b}}}:              `remove www.example.test. TXT ["b"]`,
	} {
		if got := change.String(); got != want {
			t.Errorf("String() = %q, want %q", got, want)
		}
	}
}

// TestNormalize checks that the CAA and URI records decoded from the wire,
// whose strings miekg/dns leaves raw, keep their data when written and
// encoded again.
func TestNormalize(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		`caa.example.test. 60 IN CAA 0 issue "ca.example.net; account=a\\b"`,
		`caa.example.test. 60 IN CAA 0 iodef "mailto:\"quoted\"@example.net"`,
		`caa.example.test. 60 IN CAA 0 issue "caf\195\169"`,
		`_http._tcp.example.test. 60 IN URI 10 1 "https://example.net/a\\b"`,
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		wire := make([]byte, dns.Len(rr)+1)
		n, err := dns.PackRR(rr, wire, 0, nil, false)
		if err != nil {
			t.Fatal(err)
		}
		received, _, err := dns.UnpackRR(wire[:n], 0)
		if err != nil {
			t.Fatal(err)
		}
		backend.Normalize(received)
		if got, want := received.String(), rr.String(); got != want {
			t.Errorf("Normalize() of %s writes %s", want, got)
		}
		again := make([]byte, dns.Len(received)+1)
		if m, packErr := dns.PackRR(received, again, 0, nil, false); packErr != nil || !bytes.Equal(again[:m], wire[:n]) {
			t.Errorf("Normalize() of %s encodes otherwise: %v", text, packErr)
		}
		canonical, err := backend.Canonical(rr)
		if err != nil || !dns.IsDuplicate(canonical, received) {
			t.Errorf("Canonical(%s) = %v, %v, want %s", text, canonical, err, received)
		}
	}
}
