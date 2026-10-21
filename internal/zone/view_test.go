package zone_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/memory"
	"github.com/enix/tsigoat/internal/zone"
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

// countingBackend counts the lookups of every name.
type countingBackend struct {
	*memory.Backend
	lookups map[string]int
	err     error
}

func (b *countingBackend) Lookup(ctx context.Context, zoneName, name string) ([]backend.RRset, error) {
	b.lookups[name]++
	if b.err != nil {
		return nil, b.err
	}
	return b.Backend.Lookup(ctx, zoneName, name)
}

func newBackend(t *testing.T) *countingBackend {
	t.Helper()
	b := memory.New()
	b.SetZone(testZone, records(t,
		"example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 1 7200 900 1209600 300",
		"example.test. 3600 IN NS ns1.example.test.",
		"www.example.test. 300 IN A 192.0.2.1",
		"www.example.test. 300 IN A 192.0.2.2",
		`www.example.test. 60 IN TXT "hello"`,
		"a.b.example.test. 60 IN A 192.0.2.3",
	)...)
	return &countingBackend{Backend: b, lookups: map[string]int{}}
}

func describe(changes []backend.Change) string {
	lines := make([]string, 0, len(changes))
	for _, c := range changes {
		lines = append(lines, c.String())
	}
	return strings.Join(lines, "\n")
}

func TestViewReads(t *testing.T) {
	t.Parallel()
	b := newBackend(t)
	view := zone.NewView(b, "Example.Test")

	if view.Zone() != testZone {
		t.Errorf("Zone() = %q", view.Zone())
	}
	sets, err := view.RRsets(t.Context(), "WWW.example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 2 || len(sets[dns.TypeA]) != 2 || len(sets[dns.TypeTXT]) != 1 {
		t.Errorf("RRsets() = %v", sets)
	}
	for _, name := range []string{"www.example.test.", "WWW.EXAMPLE.TEST", "a.b.example.test."} {
		if exists, existsErr := view.NameExists(t.Context(), name); existsErr != nil || !exists {
			t.Errorf("NameExists(%q) = %v, %v, want true", name, exists, existsErr)
		}
	}
	for _, name := range []string{"b.example.test.", "nowhere.example.test."} {
		if exists, existsErr := view.NameExists(t.Context(), name); existsErr != nil || exists {
			t.Errorf("NameExists(%q) = %v, %v, want false", name, exists, existsErr)
		}
	}
	if b.lookups["www.example.test."] != 1 {
		t.Errorf("www.example.test. looked up %d times, want once", b.lookups["www.example.test."])
	}

	// Reads return copies.
	set, err := view.RRset(t.Context(), "www.example.test.", dns.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	set[0].Header().Ttl = 1
	if changes := view.Changes(); len(changes) != 0 {
		t.Errorf("modifying a returned record changed the view:\n%s", describe(changes))
	}

	if _, err := view.RRset(t.Context(), "www.other.test.", dns.TypeA); err == nil {
		t.Error("reading outside the zone succeeded")
	}
}

func TestViewLookupError(t *testing.T) {
	t.Parallel()
	b := newBackend(t)
	b.err = errors.New("backend down")
	view := zone.NewView(b, testZone)

	if _, err := view.NameExists(t.Context(), "www.example.test."); !errors.Is(err, b.err) {
		t.Errorf("NameExists() error %v, want the backend error", err)
	}
	if err := view.SetRRset(t.Context(), "www.example.test.", dns.TypeA, nil); !errors.Is(err, b.err) {
		t.Errorf("SetRRset() error %v, want the backend error", err)
	}
}

func TestViewChanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		modify func(ctx context.Context, view *zone.View) error
		want   []string
	}{
		{
			name: "nothing",
			modify: func(ctx context.Context, view *zone.View) error {
				_, err := view.RRsets(ctx, "www.example.test.")
				return err
			},
		},
		{
			name: "same records in another order",
			modify: func(ctx context.Context, view *zone.View) error {
				return view.SetRRset(ctx, "www.example.test.", dns.TypeA, records(t,
					"www.example.test. 300 IN A 192.0.2.2",
					"www.example.test. 300 IN A 192.0.2.1",
				))
			},
		},
		{
			name: "deleted then restored",
			modify: func(ctx context.Context, view *zone.View) error {
				if err := view.SetRRset(ctx, "www.example.test.", dns.TypeTXT, nil); err != nil {
					return err
				}
				return view.SetRRset(ctx, "www.example.test.", dns.TypeTXT, records(t, `www.example.test. 60 IN TXT "hello"`))
			},
		},
		{
			name: "TTL only",
			modify: func(ctx context.Context, view *zone.View) error {
				return view.SetRRset(ctx, "www.example.test.", dns.TypeTXT, records(t, `www.example.test. 30 IN TXT "hello"`))
			},
			want: []string{`replace www.example.test. TXT 30 ["hello"]`},
		},
		{
			name: "every kind, deletions first",
			modify: func(ctx context.Context, view *zone.View) error {
				return errors.Join(
					view.SetRRset(ctx, "WWW.example.test.", dns.TypeTXT, nil),
					view.SetRRset(ctx, "new.example.test.", dns.TypeAAAA, records(t, "x. 60 IN AAAA 2001:db8::1")),
					view.SetRRset(ctx, "www.example.test.", dns.TypeA, records(t,
						"www.example.test. 120 IN A 192.0.2.9",
						"www.example.test. 300 IN A 192.0.2.1",
					)),
					view.SetRRset(ctx, "nowhere.example.test.", dns.TypeA, nil),
				)
			},
			want: []string{
				`remove www.example.test. TXT ["hello"]`,
				"add new.example.test. AAAA 60 [2001:db8::1]",
				"replace www.example.test. A 120 [192.0.2.1, 192.0.2.9]",
			},
		},
		{
			name: "records gained and lost, removals first",
			modify: func(ctx context.Context, view *zone.View) error {
				return view.SetRRset(ctx, "www.example.test.", dns.TypeA, records(t,
					"www.example.test. 300 IN A 192.0.2.3",
					"www.example.test. 300 IN A 192.0.2.1",
					"www.example.test. 300 IN A 192.0.2.3",
				))
			},
			want: []string{
				"remove www.example.test. A [192.0.2.2]",
				"add www.example.test. A 300 [192.0.2.3]",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := newBackend(t)
			view := zone.NewView(b, testZone)
			if err := tt.modify(t.Context(), view); err != nil {
				t.Fatal(err)
			}
			if got, want := describe(view.Changes()), strings.Join(tt.want, "\n"); got != want {
				t.Errorf("Changes():\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

func TestViewChangesApply(t *testing.T) {
	t.Parallel()
	b := newBackend(t)
	view := zone.NewView(b, testZone)
	if err := view.SetRRset(t.Context(), "www.example.test.", dns.TypeA, records(t, "www.example.test. 60 IN A 192.0.2.7")); err != nil {
		t.Fatal(err)
	}
	if err := b.Apply(t.Context(), testZone, view.Changes()); err != nil {
		t.Fatal(err)
	}

	again := zone.NewView(b, testZone)
	set, err := again.RRset(t.Context(), "www.example.test.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 || backend.RData(set[0]) != "192.0.2.7" || set[0].Header().Ttl != 60 {
		t.Errorf("after Apply(), RRset() = %v", set)
	}
}

func TestSameRecords(t *testing.T) {
	t.Parallel()

	a := records(t, "www.example.test. 300 IN A 192.0.2.1", "www.example.test. 60 IN A 192.0.2.2")
	b := records(t, "WWW.example.test. 10 IN A 192.0.2.2", "www.example.test. 10 IN A 192.0.2.1", "www.example.test. 10 IN A 192.0.2.1")
	if !zone.SameRecords(a, b) {
		t.Error("SameRecords() = false for the same records with other TTLs, order and repetitions")
	}
	if zone.SameRecords(a, a[:1]) || zone.SameRecords(a[:1], a) {
		t.Error("SameRecords() = true for a subset")
	}
	if !zone.SameRecords(nil, nil) || zone.SameRecords(nil, a) {
		t.Error("SameRecords() mishandles empty lists")
	}
	if slices.ContainsFunc(a, func(rr dns.RR) bool { return rr.Header().Ttl == 10 }) {
		t.Error("SameRecords() modified its arguments")
	}
}
