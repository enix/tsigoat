package dnsserver

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/auth"
	"github.com/enix/tsigoat/internal/config"
)

// longName returns a name of 255 octets, the longest, of labels made of c.
func longName(c string) string {
	label := strings.Repeat(c, 63)
	return label + "." + label + "." + label + "." + strings.Repeat(c, 61) + "."
}

// queryUDP sends a query over UDP, signed when signed is set, and returns the
// raw response, the response, and the MAC of the query.
func (f *fixture) queryUDP(t *testing.T, m *dns.Msg, signed bool) (raw []byte, resp *dns.Msg, requestMAC string) {
	t.Helper()
	var data []byte
	var err error
	if signed {
		m.SetTsig(keyName, dns.HmacSHA256, 300, time.Now().Unix())
		data, requestMAC, err = dns.TsigGenerateWithProvider(m, f.keyring, "", false)
	} else {
		data, err = m.Pack()
	}
	if err != nil {
		t.Fatal(err)
	}
	raw = f.exchangeBytes(t, data)
	resp = new(dns.Msg)
	if err := resp.Unpack(raw); err != nil {
		t.Fatal(err)
	}
	return raw, resp, requestMAC
}

// soaQuery returns an SOA query, with EDNS and its UDP payload size unless
// advertised is 0.
func soaQuery(name string, advertised uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeSOA)
	if advertised != 0 {
		m.SetEdns0(advertised, false)
	}
	return m
}

func TestUDPSize(t *testing.T) {
	t.Parallel()
	if got := udpSize(soaQuery(testZone, 0)); got != dns.MinMsgSize {
		t.Errorf("udpSize() without EDNS = %d, want 512", got)
	}
	m := soaQuery(testZone, 0)
	m.SetEdns0(0, false)
	if got := udpSize(m); got != dns.MinMsgSize {
		t.Errorf("udpSize() with EDNS and a payload size of 0 = %d, want 512", got)
	}
	for advertised, want := range map[uint16]int{511: 512, 512: 512, 900: 900, 1232: 1232, 4096: 1232, 65535: 1232} {
		if got := udpSize(soaQuery(testZone, advertised)); got != want {
			t.Errorf("udpSize() with EDNS and a payload size of %d = %d, want %d", advertised, got, want)
		}
	}
}

// TestLargeResponses checks that an answer to an SOA query over UDP fits in
// 512 octets without EDNS, in the payload size that the client advertises
// with EDNS, truncated with TC set when it does not, still signed then; and
// that it comes whole over TCP.
func TestLargeResponses(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// The names of the SOA alone take more than 512 octets.
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: testZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:  longName("n"), Mbox: longName("m"),
		Serial: 1, Refresh: 7200, Retry: 900, Expire: 1209600, Minttl: 300,
	}
	f.backend.SetZone(testZone, append(records(t, "example.test. 3600 IN NS ns1.example.test."), soa)...)

	for _, tt := range []struct {
		name string
		// advertised is the UDP payload size of the query, 0 without EDNS.
		advertised uint16
		signed     bool
		truncated  bool
	}{
		{"without EDNS", 0, false, true},
		{"EDNS, 512 octets", 512, false, true},
		{"EDNS, 1232 octets", 1232, false, false},
		{"without EDNS, signed", 0, true, true},
		{"EDNS, 1232 octets, signed", 1232, true, false},
	} {
		raw, resp, requestMAC := f.queryUDP(t, soaQuery(testZone, tt.advertised), tt.signed)
		size := max(int(tt.advertised), dns.MinMsgSize)
		switch {
		case len(raw) > size:
			t.Errorf("%s: a response of %d octets, for %d", tt.name, len(raw), size)
		case resp.Rcode != dns.RcodeSuccess || resp.Truncated != tt.truncated:
			t.Errorf("%s: rcode %s, truncated %v; want NOERROR, %v", tt.name,
				dns.RcodeToString[resp.Rcode], resp.Truncated, tt.truncated)
		case tt.truncated && (len(resp.Question) != 1 || len(resp.Answer)+len(resp.Ns) != 0):
			t.Errorf("%s: truncated to %v, want the question alone", tt.name, resp)
		case !tt.truncated && (len(resp.Answer) != 1 || !dns.IsDuplicate(resp.Answer[0], soa)):
			t.Errorf("%s: answer %v, want %v", tt.name, resp.Answer, soa)
		case (resp.IsEdns0() != nil) != (tt.advertised != 0):
			t.Errorf("%s: OPT record %v, want one for an EDNS query only", tt.name, resp.IsEdns0())
		}
		if tt.signed {
			if err := dns.TsigVerifyWithProvider(raw, f.keyring, requestMAC, false); err != nil {
				t.Errorf("%s: the signature of the response does not verify: %v", tt.name, err)
			}
		}
	}

	for _, signedAt := range []time.Time{{}, time.Now()} {
		resp, err := f.exchange(t, "tcp", soaQuery(testZone, 0), signedAt)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Truncated || len(resp.Answer) != 1 || resp.Len() <= dns.MinMsgSize {
			t.Errorf("over TCP, signed %v: %v, want the whole SOA", !signedAt.IsZero(), resp)
		}
	}
}

// TestCompressedResponses checks that an answer over UDP that exceeds 512
// octets, but fits once compressed, comes whole, and verifies when signed.
func TestCompressedResponses(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	label := strings.Repeat("x", 63)
	f.backend.SetZone(testZone, records(t,
		"example.test. 3600 IN SOA ns."+label+"."+label+".example.test. hostmaster."+label+"."+label+
			".example.test. 1 7200 900 1209600 300",
		"example.test. 3600 IN NS ns1.example.test.",
	)...)

	name := strings.Repeat(strings.Repeat("c", 63)+".", 3) + testZone
	for _, signed := range []bool{false, true} {
		raw, resp, requestMAC := f.queryUDP(t, soaQuery(name, 0), signed)
		if len(raw) > dns.MinMsgSize || resp.Truncated || len(resp.Ns) != 1 {
			t.Errorf("signed %v: a response of %d octets, truncated %v, %d authority records; want the SOA in 512 octets",
				signed, len(raw), resp.Truncated, len(resp.Ns))
		}
		if signed {
			if err := dns.TsigVerifyWithProvider(raw, f.keyring, requestMAC, false); err != nil {
				t.Errorf("the signature of the compressed response does not verify: %v", err)
			}
		}
		resp.Compress = false
		if resp.Len() <= dns.MinMsgSize {
			t.Errorf("signed %v: the response takes %d octets uncompressed, which leaves nothing to compress",
				signed, resp.Len())
		}
	}
}

// TestSignedResponseBoundary checks that fit reserves the exact room of the
// TSIG record: it truncates a signed response just when the response, signed
// and compressed, would exceed the size.
func TestSignedResponseBoundary(t *testing.T) {
	t.Parallel()
	keyring, err := auth.NewKeyring([]config.Key{{Name: keyName, Algorithm: config.HMACSHA256, Secret: secret}})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{keyring: keyring}
	now := time.Now().Unix()
	// response returns a signed answer, one octet longer for each step.
	response := func(step int) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(soaQuery(testZone, 0))
		resp.Answer = []dns.RR{&dns.SOA{
			Hdr: dns.RR_Header{Name: testZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
			Ns:  longName("n"), Mbox: strings.Repeat("h", step) + "." + strings.Repeat("r", 63) + ".org.",
		}}
		resp.SetTsig(keyName, dns.HmacSHA256, fudge, now)
		return resp
	}
	signed := func(m *dns.Msg) int {
		data, _, err := dns.TsigGenerateWithProvider(m, keyring, "", false)
		if err != nil {
			t.Fatal(err)
		}
		return len(data)
	}

	var crossed []int
	for step := 1; step <= 63; step++ {
		whole := response(step)
		whole.Compress = true
		wholeSize := signed(whole)
		if wholeSize == dns.MinMsgSize || wholeSize == dns.MinMsgSize+1 {
			crossed = append(crossed, wholeSize)
		}

		resp := response(step)
		s.fit(resp, dns.MinMsgSize)
		truncated := resp.Truncated
		if size := signed(resp); size > dns.MinMsgSize || truncated != (wholeSize > dns.MinMsgSize) {
			t.Errorf("%d octets whole: fit leaves %d octets, truncated %v", wholeSize, size, truncated)
		}
	}
	if len(crossed) != 2 {
		t.Errorf("the responses take %v octets about 512, want 512 and 513", crossed)
	}
}
