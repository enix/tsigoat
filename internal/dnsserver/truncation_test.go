package dnsserver

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// exchangeBytes sends packed bytes over UDP and returns the raw response.
func (f *fixture) exchangeBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var dialer net.Dialer
	conn, err := dialer.DialContext(t.Context(), "udp", f.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if deadlineErr := conn.SetDeadline(time.Now().Add(2 * time.Second)); deadlineErr != nil {
		t.Fatal(deadlineErr)
	}
	if _, writeErr := conn.Write(data); writeErr != nil {
		t.Fatal(writeErr)
	}
	buf := make([]byte, dns.MaxMsgSize)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

// truncatedUpdate returns an update signed at signedAt, whose MAC is cut to
// size octets, or replaced by change when set, and the MAC that it carries.
func (f *fixture) truncatedUpdate(t *testing.T, signedAt time.Time, size int, change func([]byte)) (data []byte, mac string) {
	t.Helper()
	m := updateMsg(t)
	m.SetTsig(keyName, dns.HmacSHA256, 300, signedAt.Unix())
	signed, _, err := dns.TsigGenerateWithProvider(m, f.keyring, "", false)
	if err != nil {
		t.Fatal(err)
	}
	out := new(dns.Msg)
	if unpackErr := out.Unpack(signed); unpackErr != nil {
		t.Fatal(unpackErr)
	}
	tsig := out.IsTsig()
	full, err := hex.DecodeString(tsig.MAC)
	if err != nil {
		t.Fatal(err)
	}
	cut := bytes.Clone(full[:size])
	if change != nil {
		change(cut)
	}
	tsig.MAC, tsig.MACSize = hex.EncodeToString(cut), uint16(len(cut))
	data, err = out.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return data, tsig.MAC
}

// mac returns the MAC that a response should carry for the request MAC. The
// verification of miekg/dns turns down NOTAUTH responses whatever their MAC:
// mac signs the response again, with the TSIG variables that it carries.
func (f *fixture) mac(t *testing.T, raw []byte, requestMAC string) string {
	t.Helper()
	m := new(dns.Msg)
	if err := m.Unpack(raw); err != nil {
		t.Fatal(err)
	}
	tsig := m.IsTsig()
	tsig.MAC, tsig.MACSize = "", 0
	_, mac, err := dns.TsigGenerateWithProvider(m, f.keyring, requestMAC, false)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}

// TestTruncatedMACs checks the answers to the requests whose MAC is
// truncated, after RFC 8945 5.2: FORMERR, without TSIG record, below the
// shortest MAC allowed; BADSIG, unsigned, for a truncated MAC that does not
// verify; BADTIME, signed, for a request signed too long ago, since the time
// comes before the truncation; BADTRUNC, signed with the truncated request
// MAC, for a truncated MAC that verifies, which tsigoat does not accept.
func TestTruncatedMACs(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	flip := func(mac []byte) { mac[0] ^= 1 }

	for _, c := range []struct {
		name     string
		signedAt time.Time
		size     int
		change   func([]byte)
		rcode    int
		// tsigError is the TSIG error of the response, -1 without TSIG
		// record.
		tsigError int
		signed    bool
	}{
		{name: "allowed truncation", signedAt: time.Now(), size: 16, rcode: dns.RcodeNotAuth, tsigError: dns.RcodeBadTrunc, signed: true},
		{name: "below the shortest", signedAt: time.Now(), size: 15, rcode: dns.RcodeFormatError, tsigError: -1},
		{name: "wrong truncated MAC", signedAt: time.Now(), size: 16, change: flip, rcode: dns.RcodeNotAuth, tsigError: dns.RcodeBadSig},
		{name: "truncated and late", signedAt: time.Now().Add(-time.Hour), size: 16, rcode: dns.RcodeNotAuth, tsigError: dns.RcodeBadTime, signed: true},
	} {
		data, requestMAC := f.truncatedUpdate(t, c.signedAt, c.size, c.change)
		raw := f.exchangeBytes(t, data)
		resp := new(dns.Msg)
		if err := resp.Unpack(raw); err != nil {
			t.Fatal(err)
		}
		if resp.Rcode != c.rcode {
			t.Errorf("%s: rcode %s, want %s", c.name, dns.RcodeToString[resp.Rcode], dns.RcodeToString[c.rcode])
		}
		tsig := resp.IsTsig()
		switch {
		case c.tsigError < 0 && tsig != nil:
			t.Errorf("%s: the response holds a TSIG record", c.name)
		case c.tsigError < 0:
		case tsig == nil:
			t.Errorf("%s: the response holds no TSIG record", c.name)
		case int(tsig.Error) != c.tsigError:
			t.Errorf("%s: TSIG error %s, want %s", c.name, dns.RcodeToString[int(tsig.Error)], dns.RcodeToString[c.tsigError])
		case c.signed && tsig.MACSize == 0:
			t.Errorf("%s: the response is unsigned", c.name)
		case !c.signed && tsig.MACSize != 0:
			t.Errorf("%s: the response is signed", c.name)
		case c.signed && tsig.Error == dns.RcodeBadTrunc:
			// The client verifies the response with the MAC that it sent.
			if want := f.mac(t, raw, requestMAC); tsig.MAC != want {
				t.Errorf("%s: the MAC of the response is %s, want %s", c.name, tsig.MAC, want)
			}
		}
	}
	if f.backend.Applied() != 0 {
		t.Error("an update with a truncated MAC was applied")
	}
}
