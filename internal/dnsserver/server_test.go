package dnsserver

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/auth"
	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/memory"
	"github.com/enix/tsigoat/internal/config"
)

const (
	testZone = "example.test."
	keyName  = "key.example."
)

var secret = []byte("0123456789abcdef0123456789abcdef")

// syncBuffer collects the logs of a server.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type fixture struct {
	server  *Server
	backend *memory.Backend
	keyring *auth.Keyring
	logs    *syncBuffer
	addr    string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	keyring, err := auth.NewKeyring([]config.Key{{Name: keyName, Algorithm: config.HMACSHA256, Secret: secret}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := auth.NewPolicy(&config.Zone{Name: testZone, Keys: []string{keyName}})
	if err != nil {
		t.Fatal(err)
	}
	b := memory.New()
	b.SetZone(testZone, records(t,
		"example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 1 7200 900 1209600 300",
		"example.test. 3600 IN NS ns1.example.test.",
	)...)

	logs := &syncBuffer{}
	server, err := New(&Options{
		Listen:  []string{"127.0.0.1:0"},
		Keyring: keyring,
		Zones:   []Zone{{Name: "Example.Test", Backend: b, BackendName: "memory", Policy: policy}},
		Logger:  slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown(): %v", err)
		}
		if t.Failed() {
			t.Logf("server logs:\n%s", logs)
		}
	})
	return &fixture{server: server, backend: b, keyring: keyring, logs: logs, addr: server.Addrs()[0]}
}

func records(t *testing.T, lines ...string) []dns.RR {
	t.Helper()
	rrs := make([]dns.RR, 0, len(lines))
	for _, line := range lines {
		rr, err := dns.NewRR(line)
		if err != nil {
			t.Fatal(err)
		}
		rrs = append(rrs, rr)
	}
	return rrs
}

// updateMsg returns an update that adds a TXT record.
func updateMsg(t *testing.T) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate(testZone)
	m.Insert(records(t, `www.example.test. 60 IN TXT "hello"`))
	return m
}

// exchange sends a message, signed when signedAt is not zero.
func (f *fixture) exchange(t *testing.T, network string, m *dns.Msg, signedAt time.Time) (*dns.Msg, error) {
	t.Helper()
	client := &dns.Client{Net: network, Timeout: 2 * time.Second, TsigProvider: f.keyring}
	if !signedAt.IsZero() {
		m.SetTsig(keyName, dns.HmacSHA256, 300, signedAt.Unix())
	}
	in, _, err := client.ExchangeContext(t.Context(), m, f.addr)
	return in, err
}

// exchangeRaw sends packed bytes over UDP and returns the raw response.
func (f *fixture) exchangeRaw(t *testing.T, data []byte) *dns.Msg {
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
	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestUpdateOverUDPAndTCP(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	for _, network := range []string{"udp", "tcp"} {
		resp, err := f.exchange(t, network, updateMsg(t), time.Now())
		if err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		if resp.Rcode != dns.RcodeSuccess || resp.IsTsig() == nil {
			t.Errorf("%s: rcode %s, signed %v", network, dns.RcodeToString[resp.Rcode], resp.IsTsig() != nil)
		}
	}
	if f.backend.Applied() != 1 {
		t.Errorf("%d changes applied, want 1: the second update changes nothing", f.backend.Applied())
	}
	if logs := f.logs.String(); !strings.Contains(logs, `msg=update`) || !strings.Contains(logs, `key=key.example.`) ||
		!strings.Contains(logs, `replace www.example.test. TXT 60`) {
		t.Errorf("the update is missing from the logs:\n%s", logs)
	}
}

func TestTSIGErrors(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// Signed an hour ago: BADTIME, signed, with the time of the server.
	// miekg/dns does not verify NOTAUTH responses, whatever their TSIG.
	signedAt := time.Now().Add(-time.Hour)
	resp, err := f.exchange(t, "udp", updateMsg(t), signedAt)
	if !errors.Is(err, dns.ErrAuth) {
		t.Fatalf("exchange error %v, want ErrAuth", err)
	}
	tsig := resp.IsTsig()
	switch {
	case resp.Rcode != dns.RcodeNotAuth || tsig == nil || tsig.Error != dns.RcodeBadTime:
		t.Errorf("response %v, want NOTAUTH with BADTIME", resp)
	case tsig.TimeSigned != uint64(signedAt.Unix()) || tsig.OtherLen != 6 || tsig.MAC == "":
		t.Errorf("BADTIME TSIG %v, want the request time, a MAC and the server time", tsig)
	}

	// Unknown key: BADKEY, unsigned.
	m := updateMsg(t)
	m.SetTsig("unknown.example.", dns.HmacSHA256, 300, time.Now().Unix())
	data, _, err := dns.TsigGenerate(m, "c2VjcmV0", "", false)
	if err != nil {
		t.Fatal(err)
	}
	resp = f.exchangeRaw(t, data)
	tsig = resp.IsTsig()
	if resp.Rcode != dns.RcodeNotAuth || tsig == nil || tsig.Error != dns.RcodeBadKey || tsig.MAC != "" {
		t.Errorf("response %v, want NOTAUTH with an unsigned BADKEY", resp)
	}
	if f.backend.Applied() != 0 {
		t.Error("a rejected update was applied")
	}
	if logs := f.logs.String(); !strings.Contains(logs, `tsig_error=BADKEY`) || !strings.Contains(logs, `tsig_error=BADTIME`) {
		t.Errorf("the TSIG failures are missing from the logs:\n%s", logs)
	}
}

func TestMalformedRequests(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	tests := []struct {
		name   string
		modify func(m *dns.Msg)
		rcode  int
	}{
		{
			name: "TSIG in the update section",
			modify: func(m *dns.Msg) {
				header := dns.RR_Header{Name: keyName, Rrtype: dns.TypeTSIG, Class: dns.ClassANY}
				m.Ns = append(m.Ns, &dns.TSIG{Hdr: header, Algorithm: dns.HmacSHA256})
			},
			rcode: dns.RcodeFormatError,
		},
		{
			name: "two OPT records",
			modify: func(m *dns.Msg) {
				m.SetEdns0(1232, false)
				m.SetEdns0(1232, false)
			},
			rcode: dns.RcodeFormatError,
		},
		{
			name: "EDNS version 1",
			modify: func(m *dns.Msg) {
				m.SetEdns0(1232, false)
				m.IsEdns0().SetVersion(1)
			},
			rcode: dns.RcodeBadVers,
		},
		{
			name:   "unknown opcode",
			modify: func(m *dns.Msg) { m.Opcode = dns.OpcodeStatus },
			rcode:  dns.RcodeNotImplemented,
		},
	}
	for _, tt := range tests {
		m := updateMsg(t)
		tt.modify(m)
		data, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		resp := f.exchangeRaw(t, data)
		if resp.Rcode != tt.rcode {
			t.Errorf("%s: rcode %s, want %s", tt.name, dns.RcodeToString[resp.Rcode], dns.RcodeToString[tt.rcode])
		}
		if m.IsEdns0() != nil && resp.IsEdns0() == nil {
			t.Errorf("%s: no OPT record in the response to an EDNS request", tt.name)
		}
	}
	if f.backend.Applied() != 0 {
		t.Error("a malformed update was applied")
	}
}

func TestResponsesAreDropped(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	m := updateMsg(t)
	m.Response = true
	client := &dns.Client{Net: "udp", Timeout: 200 * time.Millisecond}
	if _, _, err := client.ExchangeContext(t.Context(), m, f.addr); err == nil {
		t.Error("a response got an answer")
	}
}

func TestBackendFailures(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	f.backend.FailApply(errors.New("injected failure"))
	resp, err := f.exchange(t, "udp", updateMsg(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	if logs := f.logs.String(); !strings.Contains(logs, "injected failure") || !strings.Contains(logs, "level=ERROR") {
		t.Errorf("the failure is missing from the logs:\n%s", logs)
	}
	if errs := f.server.CheckZones(t.Context()); len(errs) != 0 {
		t.Errorf("CheckZones() = %v", errs)
	}

	// A zone that disappeared from the backend.
	f.backend.DeleteZone(testZone)
	resp, err = f.exchange(t, "udp", updateMsg(t), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	errs := f.server.CheckZones(t.Context())
	if len(errs) != 1 || !errors.Is(errs[0], backend.ErrZoneNotFound) || !strings.Contains(errs[0].Error(), "backend memory") {
		t.Errorf("CheckZones() = %v, want the missing zone", errs)
	}
}

// countingBackend counts the lookups.
type countingBackend struct {
	*memory.Backend
	mu      sync.Mutex
	lookups int
}

func (b *countingBackend) Lookup(ctx context.Context, zone, name string) ([]backend.RRset, error) {
	b.mu.Lock()
	b.lookups++
	b.mu.Unlock()
	return b.Backend.Lookup(ctx, zone, name)
}

func TestSOACache(t *testing.T) {
	t.Parallel()

	inner := memory.New()
	inner.SetZone(testZone, records(t,
		"example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 1 7200 900 1209600 300",
		"example.test. 3600 IN NS ns1.example.test.",
	)...)
	counting := &countingBackend{Backend: inner}
	z := &servedZone{Zone: Zone{Name: testZone, Backend: counting}, lock: make(chan struct{}, 1)}

	for range 3 {
		soa, err := z.cachedSOA(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if soa.Header().Rrtype != dns.TypeSOA || soa.Header().Name != testZone {
			t.Errorf("cachedSOA() = %v", soa)
		}
	}
	if counting.lookups != 1 {
		t.Errorf("%d lookups for three SOA queries, want 1", counting.lookups)
	}

	// Once expired, the SOA is read again.
	z.soaExpires = time.Now().Add(-time.Second)
	if _, err := z.cachedSOA(t.Context()); err != nil {
		t.Fatal(err)
	}
	if counting.lookups != 2 {
		t.Errorf("%d lookups after the expiry, want 2", counting.lookups)
	}

	// Failures are not cached.
	inner.DeleteZone(testZone)
	z.soaExpires = time.Now().Add(-time.Second)
	for range 2 {
		if _, err := z.cachedSOA(t.Context()); err == nil {
			t.Error("cachedSOA() succeeded on a missing zone")
		}
	}
	if counting.lookups != 4 {
		t.Errorf("%d lookups after two failures, want 4", counting.lookups)
	}
}

func TestZoneLockHonoursDeadlines(t *testing.T) {
	t.Parallel()

	z := &servedZone{Zone: Zone{Name: testZone}, lock: make(chan struct{}, 1)}
	if err := z.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := z.acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("acquire() of a held lock: %v, want a deadline error", err)
	}
	z.release()
	if err := z.acquire(t.Context()); err != nil {
		t.Errorf("acquire() after release(): %v", err)
	}
}

func TestStartErrors(t *testing.T) {
	t.Parallel()

	keyring, err := auth.NewKeyring(nil)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)

	// A port already taken.
	var listenConfig net.ListenConfig
	taken, err := listenConfig.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = taken.Close() }()
	server, err := New(&Options{Listen: []string{"127.0.0.1:0", taken.LocalAddr().String()}, Keyring: keyring, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	if startErr := server.Start(t.Context()); startErr == nil {
		t.Error("Start() succeeded on a port in use")
	}
	if len(server.Addrs()) != 0 {
		t.Errorf("Addrs() = %v after a failed start", server.Addrs())
	}

	if _, newErr := New(&Options{Keyring: keyring, Logger: logger}); newErr == nil {
		t.Error("New() accepted no listen address")
	}
	policy, err := auth.NewPolicy(&config.Zone{Name: testZone, AllowUnauthenticated: true})
	if err != nil {
		t.Fatal(err)
	}
	zone := Zone{Name: testZone, Backend: memory.New(), Policy: policy}
	if _, err := New(&Options{Listen: []string{"127.0.0.1:0"}, Keyring: keyring, Logger: logger, Zones: []Zone{zone, zone}}); err == nil {
		t.Error("New() accepted a duplicate zone")
	}
}

func TestRunStopsWithTheContext(t *testing.T) {
	t.Parallel()

	keyring, err := auth.NewKeyring(nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(&Options{Listen: []string{"127.0.0.1:0"}, Keyring: keyring, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return")
	}
}

func TestQueries(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	query := func(name string, qtype, qclass uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		m.Question[0].Qclass = qclass
		return m
	}
	tests := []struct {
		name      string
		msg       *dns.Msg
		signed    bool
		rcode     int
		answer    int
		authority int
	}{
		{"apex SOA, signed", query(testZone, dns.TypeSOA, dns.ClassINET), true, dns.RcodeSuccess, 1, 0},
		{"apex SOA, unsigned", query(testZone, dns.TypeSOA, dns.ClassINET), false, dns.RcodeSuccess, 1, 0},
		{"SOA below the apex", query("_acme-challenge.www."+testZone, dns.TypeSOA, dns.ClassINET), false, dns.RcodeSuccess, 0, 1},
		{"other type", query("www."+testZone, dns.TypeA, dns.ClassINET), true, dns.RcodeNotImplemented, 0, 0},
		{"unknown zone", query("other.test.", dns.TypeSOA, dns.ClassINET), true, dns.RcodeRefused, 0, 0},
		{"other class", query(testZone, dns.TypeSOA, dns.ClassCHAOS), false, dns.RcodeRefused, 0, 0},
	}
	for _, tt := range tests {
		var signedAt time.Time
		if tt.signed {
			signedAt = time.Now()
		}
		resp, err := f.exchange(t, "udp", tt.msg, signedAt)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if resp.Rcode != tt.rcode || len(resp.Answer) != tt.answer || len(resp.Ns) != tt.authority {
			t.Errorf("%s: rcode %s, %d answers, %d authority records; want %s, %d, %d", tt.name,
				dns.RcodeToString[resp.Rcode], len(resp.Answer), len(resp.Ns),
				dns.RcodeToString[tt.rcode], tt.answer, tt.authority)
		}
		if tt.rcode == dns.RcodeSuccess && !resp.Authoritative {
			t.Errorf("%s: not authoritative", tt.name)
		}
		if tt.signed && resp.IsTsig() == nil {
			t.Errorf("%s: the response to a signed query is not signed", tt.name)
		}
		for _, rr := range append(resp.Answer, resp.Ns...) {
			if rr.Header().Rrtype != dns.TypeSOA || rr.Header().Name != testZone {
				t.Errorf("%s: unexpected record %s", tt.name, rr)
			}
		}
	}

	// Two questions.
	m := query(testZone, dns.TypeSOA, dns.ClassINET)
	m.Question = append(m.Question, m.Question[0])
	data, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if resp := f.exchangeRaw(t, data); resp.Rcode != dns.RcodeFormatError {
		t.Errorf("two questions: rcode %s, want FORMERR", dns.RcodeToString[resp.Rcode])
	}
}
