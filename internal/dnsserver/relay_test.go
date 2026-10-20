package dnsserver

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/auth"
	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/memory"
	"github.com/enix/tsigoat/internal/config"
	"github.com/enix/tsigoat/internal/update"
)

// fakeRelay records the updates it relays, and answers them with its rcode or
// its error.
type fakeRelay struct {
	rcode int
	err   error
	soa   dns.RR
	// barrier, when set, holds every update until it has seen them all.
	barrier *sync.WaitGroup

	mu    sync.Mutex
	calls []relayed
}

type relayed struct {
	zone                   string
	prerequisites, updates []dns.RR
}

var _ backend.Relay = (*fakeRelay)(nil)

func (r *fakeRelay) Update(ctx context.Context, zone string, prerequisites, updates []dns.RR) (int, error) {
	r.mu.Lock()
	r.calls = append(r.calls, relayed{zone: zone, prerequisites: prerequisites, updates: updates})
	r.mu.Unlock()
	if r.barrier != nil {
		r.barrier.Done()
		done := make(chan struct{})
		go func() { r.barrier.Wait(); close(done) }()
		select {
		case <-done:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return r.rcode, r.err
}

func (r *fakeRelay) SOA(context.Context, string) (dns.RR, error) {
	if r.soa == nil {
		return nil, errors.New("no SOA")
	}
	return r.soa, nil
}

func (r *fakeRelay) relayed() []relayed {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]relayed(nil), r.calls...)
}

// newRelayFixture serves testZone through a relay. The key may update the
// TXT records of www, and test prerequisites there.
func newRelayFixture(t *testing.T, relay *fakeRelay) *fixture {
	t.Helper()

	keyring, err := auth.NewKeyring([]config.Key{{Name: keyName, Algorithm: config.HMACSHA256, Secret: secret}})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := auth.NewPolicy(&config.Zone{
		Name:   testZone,
		Policy: []config.Rule{{Key: keyName, Names: []string{"www.example.test."}, Types: []string{"TXT"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	server, err := New(&Options{
		Listen:  []string{"127.0.0.1:0"},
		Keyring: keyring,
		Zones:   []Zone{{Name: testZone, Relay: relay, BackendName: "bind", Policy: policy}},
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
	return &fixture{server: server, keyring: keyring, logs: logs, addr: server.Addrs()[0]}
}

func TestRelayedUpdate(t *testing.T) {
	t.Parallel()
	relay := &fakeRelay{rcode: dns.RcodeSuccess}
	f := newRelayFixture(t, relay)

	m := updateMsg(t)
	m.RRsetUsed(records(t, `www.example.test. 0 IN TXT "x"`))
	resp, err := f.exchange(t, "tcp", m, time.Now())
	if err != nil || resp.Rcode != dns.RcodeSuccess || resp.IsTsig() == nil {
		t.Fatalf("response %v, %v, want a signed NOERROR", resp, err)
	}

	calls := relay.relayed()
	if len(calls) != 1 {
		t.Fatalf("%d updates relayed, want 1", len(calls))
	}
	call := calls[0]
	if call.zone != testZone || len(call.prerequisites) != 1 || len(call.updates) != 1 ||
		update.Operation(call.updates[0]) != `add www.example.test. 60 TXT "hello"` {
		t.Errorf("relayed %+v, want the prerequisite and the update of the request", call)
	}
	if logs := f.logs.String(); !strings.Contains(logs, `updates="[add www.example.test. 60 TXT \"hello\"]"`) ||
		!strings.Contains(logs, "rcode=NOERROR") {
		t.Errorf("the relayed update is missing from the logs:\n%s", logs)
	}
}

func TestRelayedOutcomes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		relay *fakeRelay
		rcode int
		log   string
	}{
		{
			"failed prerequisite", &fakeRelay{rcode: dns.RcodeNXRrset}, dns.RcodeNXRrset,
			`reason="answered by the server of backend bind"`,
		},
		{
			"relay failure", &fakeRelay{err: errors.New("refused by the server")}, dns.RcodeServerFailure,
			`error="relaying the update: refused by the server"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newRelayFixture(t, tt.relay)
			resp, err := f.exchange(t, "udp", updateMsg(t), time.Now())
			if err != nil || resp.Rcode != tt.rcode {
				t.Fatalf("response %v, %v, want %s", resp, err, dns.RcodeToString[tt.rcode])
			}
			if logs := f.logs.String(); !strings.Contains(logs, tt.log) {
				t.Errorf("the logs lack %s:\n%s", tt.log, logs)
			}
		})
	}
}

// TestRelayAfterChecks checks that the updates that tsigoat turns down never
// reach the relay.
func TestRelayAfterChecks(t *testing.T) {
	t.Parallel()
	relay := &fakeRelay{rcode: dns.RcodeSuccess}
	f := newRelayFixture(t, relay)

	tests := []struct {
		name  string
		msg   func() *dns.Msg
		rcode int
	}{
		{"policy", func() *dns.Msg {
			m := new(dns.Msg)
			m.SetUpdate(testZone)
			m.Insert(records(t, "www.example.test. 60 IN A 192.0.2.1"))
			return m
		}, dns.RcodeRefused},
		{"prerequisite out of the policy", func() *dns.Msg {
			m := updateMsg(t)
			m.NameUsed(records(t, "other.example.test. 0 IN A 192.0.2.1"))
			return m
		}, dns.RcodeRefused},
		{"prescan", func() *dns.Msg {
			m := new(dns.Msg)
			m.SetUpdate(testZone)
			m.Insert(records(t, `www.example.org. 60 IN TXT "elsewhere"`))
			return m
		}, dns.RcodeNotZone},
	}
	for _, tt := range tests {
		resp, err := f.exchange(t, "udp", tt.msg(), time.Now())
		if err != nil || resp.Rcode != tt.rcode {
			t.Errorf("%s: response %v, %v, want %s", tt.name, resp, err, dns.RcodeToString[tt.rcode])
		}
	}
	if calls := relay.relayed(); len(calls) != 0 {
		t.Errorf("relayed %+v, want nothing", calls)
	}
}

// TestRelayedUpdatesRunConcurrently checks that the relayed updates of a zone
// do not wait for each other: the server of the relay serializes them.
func TestRelayedUpdatesRunConcurrently(t *testing.T) {
	t.Parallel()
	const updates = 2
	barrier := &sync.WaitGroup{}
	barrier.Add(updates)
	f := newRelayFixture(t, &fakeRelay{rcode: dns.RcodeSuccess, barrier: barrier})

	rcodes := make([]int, updates)
	var wg sync.WaitGroup
	for i := range updates {
		wg.Go(func() {
			resp, err := f.exchange(t, "tcp", updateMsg(t), time.Now())
			if err != nil {
				t.Errorf("update %d: %v", i, err)
				return
			}
			rcodes[i] = resp.Rcode
		})
	}
	wg.Wait()
	for i, rcode := range rcodes {
		if rcode != dns.RcodeSuccess {
			t.Errorf("update %d: %s, want NOERROR: the relayed updates waited for each other", i, dns.RcodeToString[rcode])
		}
	}
}

func TestRelayedSOAQuery(t *testing.T) {
	t.Parallel()
	soa := records(t, "example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 7 7200 900 1209600 300")[0]
	f := newRelayFixture(t, &fakeRelay{soa: soa})

	m := new(dns.Msg)
	m.SetQuestion("www.example.test.", dns.TypeSOA)
	resp, err := f.exchange(t, "udp", m, time.Time{})
	if err != nil || resp.Rcode != dns.RcodeSuccess || !resp.Authoritative || len(resp.Ns) != 1 ||
		!dns.IsDuplicate(resp.Ns[0], soa) {
		t.Fatalf("response %v, %v, want the SOA of the relay in the authority section", resp, err)
	}
	if errs := f.server.CheckZones(t.Context()); len(errs) != 0 {
		t.Errorf("CheckZones() = %v", errs)
	}
}

func TestNewZoneBackendOrRelay(t *testing.T) {
	t.Parallel()
	keyring, err := auth.NewKeyring(nil)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := auth.NewPolicy(&config.Zone{Name: testZone, AllowUnauthenticated: true})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.DiscardHandler)
	for name, z := range map[string]Zone{
		"neither": {Name: testZone, Policy: policy},
		"both":    {Name: testZone, Policy: policy, Backend: memory.New(), Relay: &fakeRelay{}},
	} {
		if _, err := New(&Options{Listen: []string{"127.0.0.1:0"}, Keyring: keyring, Zones: []Zone{z}, Logger: logger}); err == nil {
			t.Errorf("New() accepted a zone with %s a backend and a relay", name)
		}
	}
}
