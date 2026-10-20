package memory_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/backendtest"
	"github.com/enix/tsigoat/internal/backend/memory"
)

const testZone = "example.test."

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

func newBackend(t *testing.T) *memory.Backend {
	t.Helper()
	b := memory.New()
	b.SetZone(testZone, records(t,
		"example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 1 7200 900 1209600 300",
		"example.test. 3600 IN NS ns1.example.test.",
		"WWW.example.test. 300 IN A 192.0.2.1",
		"www.example.test. 60 IN A 192.0.2.2",
		`www.example.test. 60 IN TXT "hello"`,
	)...)
	return b
}

func dump(t *testing.T, b *memory.Backend) string {
	t.Helper()
	rrs, err := b.Records(testZone)
	if err != nil {
		t.Fatal(err)
	}
	lines := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		lines = append(lines, strings.Join(strings.Fields(rr.String()), " "))
	}
	return strings.Join(lines, "\n")
}

func TestLookup(t *testing.T) {
	t.Parallel()
	b := newBackend(t)

	sets, err := b.Lookup(t.Context(), "Example.TEST", "www.EXAMPLE.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 2 || sets[0].Type != dns.TypeA || sets[1].Type != dns.TypeTXT {
		t.Fatalf("Lookup() = %v, want the A and TXT RRsets", sets)
	}
	a := sets[0]
	if a.Name != "www.example.test." || a.TTL != 300 || len(a.Records) != 2 {
		t.Errorf("A RRset = %+v, want two records named www.example.test. with the TTL of the first one", a)
	}
	for _, rr := range a.Records {
		if rr.Header().Name != "www.example.test." || rr.Header().Ttl != 300 {
			t.Errorf("record %s does not carry the name and TTL of its RRset", rr)
		}
	}

	// Records are copies.
	a.Records[0].Header().Ttl = 1
	again, err := b.Lookup(t.Context(), testZone, "www.example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Records[0].Header().Ttl != 300 {
		t.Error("modifying a looked up record modified the backend")
	}

	if sets, err := b.Lookup(t.Context(), testZone, "nowhere.example.test."); err != nil || len(sets) != 0 {
		t.Errorf("Lookup() of an absent name = %v, %v, want nothing", sets, err)
	}
	if _, err := b.Lookup(t.Context(), "other.test.", "other.test."); !errors.Is(err, backend.ErrZoneNotFound) {
		t.Errorf("Lookup() in an unknown zone: error %v, want ErrZoneNotFound", err)
	}
}

func TestApply(t *testing.T) {
	t.Parallel()
	b := newBackend(t)

	err := b.Apply(t.Context(), testZone, []backend.Change{
		{Op: backend.Delete, RRset: backend.RRset{Name: "www.example.test.", Type: dns.TypeA}},
		{Op: backend.Replace, RRset: backend.RRset{
			Name: "www.example.test.", Type: dns.TypeTXT, TTL: 30,
			Records: records(t, `www.example.test. 60 IN TXT "a"`, `www.example.test. 60 IN TXT "b"`),
		}},
		{Op: backend.Replace, RRset: backend.RRset{
			Name: "new.example.test.", Type: dns.TypeAAAA, TTL: 60,
			Records: records(t, "new.example.test. 60 IN AAAA 2001:db8::1"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"example.test. 3600 IN NS ns1.example.test.",
		"example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 1 7200 900 1209600 300",
		"new.example.test. 60 IN AAAA 2001:db8::1",
		`www.example.test. 30 IN TXT "a"`,
		`www.example.test. 30 IN TXT "b"`,
	}, "\n")
	if got := dump(t, b); got != want {
		t.Errorf("zone after Apply():\n%s\nwant:\n%s", got, want)
	}
	if b.Applied() != 1 {
		t.Errorf("Applied() = %d, want 1", b.Applied())
	}
}

func TestApplyIsAtomic(t *testing.T) {
	t.Parallel()

	valid := backend.Change{Op: backend.Delete, RRset: backend.RRset{Name: "www.example.test.", Type: dns.TypeA}}
	tests := []struct {
		name    string
		zone    string
		changes []backend.Change
		fail    error
		target  error
	}{
		{
			name: "change outside the zone",
			zone: testZone,
			changes: []backend.Change{valid, {Op: backend.Delete, RRset: backend.RRset{
				Name: "www.other.test.", Type: dns.TypeA,
			}}},
		},
		{
			name: "replace without records",
			zone: testZone,
			changes: []backend.Change{valid, {Op: backend.Replace, RRset: backend.RRset{
				Name: "www.example.test.", Type: dns.TypeTXT, TTL: 60,
			}}},
		},
		{
			name:    "unknown operation",
			zone:    testZone,
			changes: []backend.Change{valid, {RRset: backend.RRset{Name: "www.example.test.", Type: dns.TypeTXT}}},
		},
		{
			name:    "unknown zone",
			zone:    "other.test.",
			changes: []backend.Change{valid},
			target:  backend.ErrZoneNotFound,
		},
		{
			name:    "injected failure",
			zone:    testZone,
			changes: []backend.Change{valid},
			fail:    errors.New("injected"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := newBackend(t)
			before := dump(t, b)
			b.FailApply(tt.fail)

			err := b.Apply(t.Context(), tt.zone, tt.changes)
			if err == nil {
				t.Fatal("Apply() succeeded")
			}
			if tt.target != nil && !errors.Is(err, tt.target) {
				t.Errorf("Apply() error %v, want %v", err, tt.target)
			}
			if tt.fail != nil && !errors.Is(err, tt.fail) {
				t.Errorf("Apply() error %v, want %v", err, tt.fail)
			}
			if after := dump(t, b); after != before {
				t.Errorf("a failed Apply() modified the zone:\n%s", after)
			}
			if b.Applied() != 0 {
				t.Errorf("Applied() = %d, want 0", b.Applied())
			}
		})
	}
}

func TestDeleteZone(t *testing.T) {
	t.Parallel()
	b := newBackend(t)
	b.DeleteZone("Example.Test")
	if _, err := b.Lookup(t.Context(), testZone, testZone); !errors.Is(err, backend.ErrZoneNotFound) {
		t.Errorf("Lookup() after DeleteZone(): error %v, want ErrZoneNotFound", err)
	}
}

func TestSetZoneCopiesRecords(t *testing.T) {
	t.Parallel()

	rrs := records(t, "example.test. 3600 IN NS ns1.example.test.")
	b := memory.New()
	b.SetZone(testZone, rrs...)
	rrs[0].Header().Ttl = 1
	if got := dump(t, b); !strings.Contains(got, " 3600 ") {
		t.Errorf("modifying a record given to SetZone() modified the backend: %s", got)
	}
}

// TestConformance runs the conformance suite of the backends.
func TestConformance(t *testing.T) {
	t.Parallel()
	suite := &backendtest.Suite{Backend: newBackend(t), Zone: testZone, Base: "conformance." + testZone}
	suite.Run(t)
}
