package dnsserver

import (
	"bytes"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/auth"
	"github.com/enix/tsigoat/internal/backend/memory"
	"github.com/enix/tsigoat/internal/config"
)

// fakeWriter records the response of the handler.
type fakeWriter struct {
	tsigStatus error
	written    *dns.Msg
}

func (*fakeWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

func (*fakeWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
}

func (w *fakeWriter) WriteMsg(m *dns.Msg) error {
	w.written = m
	return nil
}

func (*fakeWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (*fakeWriter) Close() error {
	return nil
}

func (w *fakeWriter) TsigStatus() error {
	return w.tsigStatus
}

func (*fakeWriter) TsigTimersOnly(bool) {}

func (*fakeWriter) Hijack() {}

const openZone = "open.test."

// fuzzServer returns a server, not listening, for a secured zone and an
// open zone.
func fuzzServer(f *testing.F) (*Server, *memory.Backend, *auth.Keyring) {
	f.Helper()
	keyring, err := auth.NewKeyring([]config.Key{{Name: keyName, Algorithm: config.HMACSHA256, Secret: secret}})
	if err != nil {
		f.Fatal(err)
	}
	secured, err := auth.NewPolicy(&config.Zone{Name: testZone, Keys: []string{keyName}})
	if err != nil {
		f.Fatal(err)
	}
	open, err := auth.NewPolicy(&config.Zone{Name: openZone, AllowUnauthenticated: true})
	if err != nil {
		f.Fatal(err)
	}
	b := memory.New()
	for _, zone := range []string{testZone, openZone} {
		soa, soaErr := dns.NewRR(zone + " 3600 IN SOA ns1." + zone + " hostmaster." + zone + " 1 7200 900 1209600 300")
		ns, nsErr := dns.NewRR(zone + " 3600 IN NS ns1." + zone)
		if soaErr != nil || nsErr != nil {
			f.Fatal(soaErr, nsErr)
		}
		b.SetZone(zone, soa, ns)
	}
	server, err := New(&Options{
		Listen:  []string{"127.0.0.1:0"},
		Keyring: keyring,
		Zones: []Zone{
			{Name: testZone, Backend: b, Policy: secured},
			{Name: openZone, Backend: b, Policy: open},
		},
		Logger:  slog.New(slog.DiscardHandler),
		Timeout: time.Second,
	})
	if err != nil {
		f.Fatal(err)
	}
	return server, b, keyring
}

func fuzzSeeds(f *testing.F, keyring *auth.Keyring) {
	f.Helper()
	add := func(m *dns.Msg, signed bool) {
		var data []byte
		var err error
		if signed {
			m.SetTsig(keyName, dns.HmacSHA256, 300, time.Now().Unix())
			data, _, err = dns.TsigGenerateWithProvider(m, keyring, "", false)
		} else {
			data, err = m.Pack()
		}
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	rr := func(text string) dns.RR {
		parsed, err := dns.NewRR(text)
		if err != nil {
			f.Fatal(err)
		}
		return parsed
	}

	for _, zone := range []string{testZone, openZone} {
		m := new(dns.Msg)
		m.SetUpdate(zone)
		m.Insert([]dns.RR{rr("www." + zone + ` 60 IN TXT "hello"`), rr("www." + zone + " 60 IN A 192.0.2.1")})
		add(m, zone == testZone)

		m = new(dns.Msg)
		m.SetUpdate(zone)
		m.NameNotUsed([]dns.RR{rr("new." + zone + " 0 IN A 0.0.0.0")})
		m.RemoveName([]dns.RR{rr(zone + " 0 IN A 0.0.0.0")})
		m.Insert([]dns.RR{rr(zone + " 60 IN CNAME target.example.")})
		add(m, false)

		m = new(dns.Msg)
		m.SetQuestion(zone, dns.TypeSOA)
		add(m, zone == testZone)
	}
	m := new(dns.Msg)
	m.SetNotify(testZone)
	add(m, true)
}

// FuzzServeDNS feeds arbitrary messages to the handler: it must answer
// every one of them with a message that packs, and the zones must keep their
// SOA and apex NS.
func FuzzServeDNS(f *testing.F) {
	server, b, keyring := fuzzServer(f)
	fuzzSeeds(f, keyring)

	f.Fuzz(func(t *testing.T, data []byte) {
		req := new(dns.Msg)
		if err := req.Unpack(data); err != nil {
			return
		}
		w := &fakeWriter{}
		if req.IsTsig() != nil {
			w.tsigStatus = dns.TsigVerifyWithProvider(bytes.Clone(data), keyring, "", false)
		}
		server.ServeDNS(w, req)
		if w.written == nil {
			t.Fatal("no response")
		}
		if _, err := w.written.Pack(); err != nil {
			t.Fatalf("the response does not pack: %v\n%v", err, w.written)
		}
		for _, zone := range []string{testZone, openZone} {
			records, err := b.Records(zone)
			if err != nil {
				t.Fatal(err)
			}
			var soa, ns int
			for _, rr := range records {
				switch {
				case rr.Header().Rrtype == dns.TypeSOA:
					soa++
				case rr.Header().Rrtype == dns.TypeNS && rr.Header().Name == zone:
					ns++
				}
			}
			if soa != 1 || ns == 0 {
				t.Fatalf("zone %s has %d SOA and %d apex NS records", zone, soa, ns)
			}
		}
	})
}
