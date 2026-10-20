package update_test

import (
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/update"
)

// wireName returns a domain name in wire format, uncompressed.
func wireName(name string) []byte {
	var b []byte
	for _, label := range dns.SplitDomainName(name) {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0)
}

// emptyA returns, built byte by byte rather than through miekg/dns, an UPDATE
// of example.test. whose prerequisite section, or update section, holds the
// record www.example.test. IN A with an RDLENGTH of zero: no address.
func emptyA(prerequisite bool) []byte {
	b := []byte{
		0x12, 0x34, // ID
		0x28, 0x00, // QR 0, opcode UPDATE (5)
		0, 1, // ZOCOUNT
		0, 0, // PRCOUNT
		0, 0, // UPCOUNT
		0, 0, // ADCOUNT
	}
	ttl := byte(60)
	if prerequisite {
		b[7], ttl = 1, 0
	} else {
		b[9] = 1
	}
	b = append(b, wireName("example.test.")...)
	b = append(b, 0, 6, 0, 1) // SOA, IN
	b = append(b, wireName("www.example.test.")...)
	return append(b, 0, 1, 0, 1, 0, 0, 0, ttl, 0, 0) // A, IN, TTL, RDLENGTH 0
}

// parse checks a packed message with update.Parse.
func parse(t *testing.T, data []byte) error {
	t.Helper()
	m := new(dns.Msg)
	if err := m.Unpack(data); err != nil {
		t.Fatalf("unpacking the fixture: %v", err)
	}
	zoneName, class, err := update.ParseZone(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = update.Parse(m, zoneName, class, []string{testZone})
	return err
}

// TestMissingRDATAOnTheWire checks that an addition or a value-dependent
// prerequisite without RDATA, as it comes on the wire, gets FORMERR.
func TestMissingRDATAOnTheWire(t *testing.T) {
	t.Parallel()
	for _, prerequisite := range []bool{false, true} {
		err := parse(t, emptyA(prerequisite))
		if err == nil || rcodeOf(t, err) != dns.RcodeFormatError || !strings.Contains(err.Error(), "RDATA") {
			t.Errorf("Parse() of an A record without address (prerequisite %t) = %v, want FORMERR", prerequisite, err)
		}
	}
}

// emptyRecord returns an UPDATE of example.test. that adds, or deletes with
// class NONE, a record of the given type with an RDLENGTH of zero, as miekg/dns
// writes the generic form of RFC 3597.
func emptyRecord(t *testing.T, rrtype, class uint16) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate(testZone)
	ttl := uint32(60)
	if class == dns.ClassNONE {
		ttl = 0
	}
	m.Ns = []dns.RR{&dns.RFC3597{Hdr: dns.RR_Header{Name: "www." + testZone, Rrtype: rrtype, Class: class, Ttl: ttl}}}
	data, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestMissingRDATAByType checks the types whose RDATA may be empty, and some
// of those whose RDATA may not, among them types whose fields miekg/dns
// encodes again into some bytes.
func TestMissingRDATAByType(t *testing.T) {
	t.Parallel()
	for _, rrtype := range []uint16{
		dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeTXT, dns.TypeMX, dns.TypeSRV, dns.TypeCAA,
		dns.TypeHINFO, dns.TypeSOA, dns.TypeSVCB, dns.TypeHTTPS, dns.TypeCSYNC,
	} {
		err := parse(t, emptyRecord(t, rrtype, dns.ClassINET))
		if err == nil || rcodeOf(t, err) != dns.RcodeFormatError {
			t.Errorf("Parse() of an empty %s addition = %v, want FORMERR", dns.Type(rrtype), err)
		}
		// Deleting a record without RDATA matches no record, but is no error.
		if err := parse(t, emptyRecord(t, rrtype, dns.ClassNONE)); err != nil {
			t.Errorf("Parse() of an empty %s deletion = %v", dns.Type(rrtype), err)
		}
	}
	for _, rrtype := range []uint16{dns.TypeNULL, dns.TypeAPL, dns.TypeEID, dns.TypeNIMLOC, 65280} {
		if err := parse(t, emptyRecord(t, rrtype, dns.ClassINET)); err != nil {
			t.Errorf("Parse() of an empty %s addition = %v, which its type allows", dns.Type(rrtype), err)
		}
	}
}

// TestRDATAOfBuiltRecords checks that records built in memory, whose header
// holds no RDLENGTH, pass when they hold data, received or not.
func TestRDATAOfBuiltRecords(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		"www.example.test. 60 IN A 192.0.2.1",
		"www.example.test. 60 IN A 0.0.0.0",
		"www.example.test. 60 IN MX 0 .",
		`www.example.test. 60 IN TXT ""`,
		"www.example.test. 60 IN SRV 0 0 0 .",
	} {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		m := new(dns.Msg)
		m.SetUpdate(testZone)
		m.Insert([]dns.RR{rr})
		if _, err := update.Parse(m, testZone, dns.ClassINET, []string{testZone}); err != nil {
			t.Errorf("Parse(%s) built in memory = %v", text, err)
		}
		if _, err := update.Parse(roundtrip(t, m), testZone, dns.ClassINET, []string{testZone}); err != nil {
			t.Errorf("Parse(%s) received = %v", text, err)
		}
	}
}
