// Package zone provides the working view of a zone used by the update engine.
//
// A View reads the RRsets of a name from the backend the first time the name
// is touched, keeps every modification in memory, and finally computes the
// changes of each RRset between the backend content and its own. Nothing
// reaches the backend before the update is complete, which makes updates
// atomic and lets the prerequisites see a consistent state.
package zone

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
)

// View is the working view of a zone during one update. It is not safe for
// concurrent use.
type View struct {
	backend backend.Backend
	zone    string
	// original and current hold, for every name read so far, its RRsets by
	// type: as read from the backend, and as modified by the update.
	original map[string]map[uint16][]dns.RR
	current  map[string]map[uint16][]dns.RR
}

// NewView returns a view of the zone held by the backend.
func NewView(b backend.Backend, zone string) *View {
	return &View{
		backend:  b,
		zone:     dns.CanonicalName(zone),
		original: map[string]map[uint16][]dns.RR{},
		current:  map[string]map[uint16][]dns.RR{},
	}
}

// Zone returns the canonical name of the zone.
func (v *View) Zone() string {
	return v.zone
}

// RRsets returns copies of the RRsets owned by name, by type.
func (v *View) RRsets(ctx context.Context, name string) (map[uint16][]dns.RR, error) {
	sets, err := v.load(ctx, name)
	if err != nil {
		return nil, err
	}
	copies := make(map[uint16][]dns.RR, len(sets))
	for rrtype, records := range sets {
		copies[rrtype] = copyRecords(records)
	}
	return copies, nil
}

// RRset returns copies of the records of one RRset, nil when it does not
// exist.
func (v *View) RRset(ctx context.Context, name string, rrtype uint16) ([]dns.RR, error) {
	sets, err := v.load(ctx, name)
	if err != nil {
		return nil, err
	}
	return copyRecords(sets[rrtype]), nil
}

// NameExists reports whether at least one record is owned by name. Empty
// non-terminals do not count, as RFC 2136 2.4.4 requires.
func (v *View) NameExists(ctx context.Context, name string) (bool, error) {
	sets, err := v.load(ctx, name)
	if err != nil {
		return false, err
	}
	return len(sets) > 0, nil
}

// SetRRset replaces an RRset with copies of the records; no record deletes
// the RRset. Every record takes the owner name, the type and the TTL of the
// first one.
func (v *View) SetRRset(ctx context.Context, name string, rrtype uint16, records []dns.RR) error {
	sets, err := v.load(ctx, name)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		delete(sets, rrtype)
		return nil
	}
	ttl := records[0].Header().Ttl
	set := copyRecords(records)
	for _, rr := range set {
		rr.Header().Name = dns.CanonicalName(name)
		rr.Header().Rrtype = rrtype
		rr.Header().Ttl = ttl
	}
	sets[rrtype] = set
	return nil
}

// Changes returns the changes from the backend content to the view, by
// RRset. An RRset that keeps its TTL, or that the update creates or deletes,
// changes by the records that it loses and gains, Remove and Add, so that the
// records that other instances write meanwhile survive; an RRset whose TTL
// changes is replaced whole. The removals come first, then the replacements
// and the additions, each sorted by name and type: for the backends that
// check every change against the state that the previous ones leave, as
// PowerDNS does within a PATCH, an update may then replace a CNAME with
// other data, or the reverse.
func (v *View) Changes() []backend.Change {
	var removals, others []backend.Change
	for _, name := range slices.Sorted(maps.Keys(v.current)) {
		before, after := v.original[name], v.current[name]
		types := slices.Sorted(maps.Keys(before))
		for rrtype := range after {
			if _, ok := before[rrtype]; !ok {
				types = append(types, rrtype)
			}
		}
		slices.Sort(types)
		for _, rrtype := range types {
			old, now := before[rrtype], after[rrtype]
			if len(old) > 0 && len(now) > 0 && old[0].Header().Ttl != now[0].Header().Ttl {
				others = append(others, backend.Change{
					Op:    backend.Replace,
					RRset: backend.RRset{Name: name, Type: rrtype, TTL: now[0].Header().Ttl, Records: copyRecords(now)},
				})
				continue
			}
			if gone := missing(old, now); len(gone) > 0 {
				removals = append(removals, backend.Change{
					Op:    backend.Remove,
					RRset: backend.RRset{Name: name, Type: rrtype, TTL: old[0].Header().Ttl, Records: gone},
				})
			}
			if added := missing(now, old); len(added) > 0 {
				others = append(others, backend.Change{
					Op:    backend.Add,
					RRset: backend.RRset{Name: name, Type: rrtype, TTL: now[0].Header().Ttl, Records: added},
				})
			}
		}
	}
	return append(removals, others...)
}

// RaiseTTLs raises to minTTL the TTL of the RRsets that the update writes
// below it, those that it creates, adds records to or gives another TTL, and
// returns them, such as "www.example.org. TXT 30 to 60". It comes before
// Changes, so that adding a record to an RRset that has the minimum TTL stays
// an addition, which keeps the records that other instances add meanwhile.
func (v *View) RaiseTTLs(minTTL uint32) []string {
	var raised []string
	for _, name := range slices.Sorted(maps.Keys(v.current)) {
		before, after := v.original[name], v.current[name]
		for _, rrtype := range slices.Sorted(maps.Keys(after)) {
			old, now := before[rrtype], after[rrtype]
			if len(now) == 0 || now[0].Header().Ttl >= minTTL {
				continue
			}
			ttl := now[0].Header().Ttl
			if len(old) > 0 && old[0].Header().Ttl == ttl && len(missing(now, old)) == 0 {
				continue
			}
			raised = append(raised, fmt.Sprintf("%s %s %d to %d", name, dns.Type(rrtype), ttl, minTTL))
			for _, rr := range now {
				rr.Header().Ttl = minTTL
			}
		}
	}
	return raised
}

// missing returns copies of the records of a that b does not hold, once each.
func missing(a, b []dns.RR) []dns.RR {
	var out []dns.RR
	for _, rr := range a {
		duplicate := func(other dns.RR) bool { return dns.IsDuplicate(other, rr) }
		if !slices.ContainsFunc(b, duplicate) && !slices.ContainsFunc(out, duplicate) {
			out = append(out, dns.Copy(rr))
		}
	}
	return out
}

// load reads the RRsets of a name from the backend, once.
func (v *View) load(ctx context.Context, name string) (map[uint16][]dns.RR, error) {
	name = dns.CanonicalName(name)
	if sets, ok := v.current[name]; ok {
		return sets, nil
	}
	if !dns.IsSubDomain(v.zone, name) {
		return nil, fmt.Errorf("%s is outside zone %s", name, v.zone)
	}

	rrsets, err := v.backend.Lookup(ctx, v.zone, name)
	if err != nil {
		return nil, fmt.Errorf("looking up %s: %w", name, err)
	}
	original := make(map[uint16][]dns.RR, len(rrsets))
	current := make(map[uint16][]dns.RR, len(rrsets))
	for _, set := range rrsets {
		if len(set.Records) == 0 {
			continue
		}
		records := make([]dns.RR, 0, len(set.Records))
		for _, rr := range set.Records {
			// Records parsed from text may hold their RDATA in another form
			// than the records of an update, which dns.IsDuplicate would tell
			// apart.
			c, err := backend.Canonical(rr)
			if err != nil {
				return nil, fmt.Errorf("reading %s %s: %w", name, dns.Type(set.Type), err)
			}
			c.Header().Name = name
			c.Header().Ttl = set.TTL
			records = append(records, c)
		}
		original[set.Type] = copyRecords(records)
		current[set.Type] = copyRecords(records)
	}
	v.original[name] = original
	v.current[name] = current
	return current, nil
}

// SameRecords reports whether two lists hold the same records, ignoring the
// TTL, the order and repetitions.
func SameRecords(a, b []dns.RR) bool {
	contains := func(set []dns.RR, rr dns.RR) bool {
		return slices.ContainsFunc(set, func(other dns.RR) bool { return dns.IsDuplicate(other, rr) })
	}
	for _, rr := range a {
		if !contains(b, rr) {
			return false
		}
	}
	for _, rr := range b {
		if !contains(a, rr) {
			return false
		}
	}
	return true
}

func copyRecords(records []dns.RR) []dns.RR {
	if records == nil {
		return nil
	}
	copies := make([]dns.RR, len(records))
	for i, rr := range records {
		copies[i] = dns.Copy(rr)
	}
	slices.SortStableFunc(copies, func(a, b dns.RR) int { return cmp.Compare(a.String(), b.String()) })
	return copies
}
