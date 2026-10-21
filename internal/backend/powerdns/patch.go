package powerdns

import (
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
)

// seenTTL bounds the life of what a lookup read: an update reads its names,
// then applies its changes, within its deadline and its recovery budget.
const seenTTL = time.Minute

// seenName holds the RRsets of a name as a lookup read them, by type name.
type seenName struct {
	read time.Time
	sets map[string]seenRRset
}

// seenRRset is an RRset as a lookup read it.
type seenRRset struct {
	ttl uint32
	// records holds its records as the API wrote them, the disabled ones
	// too.
	records []record
}

// rrsetKey identifies an RRset of a zone.
type rrsetKey struct {
	name   string
	rrtype uint16
}

// keepSeen records what the lookup of a name read, and forgets what lookups
// read too long ago.
func (b *Backend) keepSeen(zone, name string, seen seenName) {
	b.seenMu.Lock()
	defer b.seenMu.Unlock()
	for key, old := range b.seen {
		if time.Since(old.read) > seenTTL {
			delete(b.seen, key)
		}
	}
	b.seen[seenKey(zone, name)] = seen
}

// lookedUp returns what the last lookup of a name read, and whether it is
// recent enough to rely on.
func (b *Backend) lookedUp(zone, name string) (seenName, bool) {
	b.seenMu.Lock()
	defer b.seenMu.Unlock()
	seen, ok := b.seen[seenKey(zone, name)]
	return seen, ok && time.Since(seen.read) <= seenTTL
}

// seenRRset returns an RRset as the last lookup of its name read it, and
// whether it existed then.
func (b *Backend) seenRRset(zone, name, typ string) (seenRRset, bool) {
	seen, ok := b.lookedUp(zone, name)
	if !ok {
		return seenRRset{}, false
	}
	set, ok := seen.sets[typ]
	return set, ok
}

func seenKey(zone, name string) string {
	return dns.CanonicalName(zone) + " " + dns.CanonicalName(name)
}

// patchOf returns the RRsets of the PATCH request that applies the changes.
//
// Replace and Delete become REPLACE and DELETE. PowerDNS replaces whole
// RRsets, and tsigoat does not see the disabled records: a REPLACE carries
// those that the lookup of the name read, but those that the RRset enables
// again.
//
// Add and Remove become one EXTEND or PRUNE per record, which PowerDNS
// applies to the records of the RRset as they stand, so that concurrent
// updates of its other records survive. PRUNE compares contents as text: it
// takes the content of a record as the API wrote it. PowerDNS drops the
// disabled records of the RRsets that EXTEND and PRUNE change: further EXTEND
// put them back, last. A server without EXTEND and PRUNE gets the REPLACE of
// the RRset as its lookup read it, the records removed and added.
func (b *Backend) patchOf(zone string, changes []backend.Change, recordOps bool) ([]rrset, error) {
	d := deltasOf(changes)
	var sets []rrset
	var touched []rrsetKey
	for _, change := range changes {
		k := rrsetKey{name: dns.CanonicalName(change.RRset.Name), rrtype: change.RRset.Type}
		if change.Op == backend.Add || change.Op == backend.Remove {
			first := !slices.Contains(touched, k)
			if first {
				touched = append(touched, k)
			}
			entries, err := b.recordChange(zone, change, first, recordOps, d)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", change, err)
			}
			sets = append(sets, entries...)
			continue
		}
		set, err := toAPI(change)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", change, err)
		}
		if change.Op == backend.Replace {
			b.withDisabled(zone, &set)
		}
		sets = append(sets, set)
	}
	if recordOps {
		for _, k := range touched {
			sets = append(sets, b.disabledAgain(zone, k, d.added[k], d.ttls[k])...)
		}
	}
	return sets, nil
}

// deltas holds the records that changes add and remove, by RRset, with the
// TTL of the RRset.
type deltas struct {
	added, removed map[rrsetKey][]dns.RR
	ttls           map[rrsetKey]uint32
}

func deltasOf(changes []backend.Change) *deltas {
	d := &deltas{added: map[rrsetKey][]dns.RR{}, removed: map[rrsetKey][]dns.RR{}, ttls: map[rrsetKey]uint32{}}
	for _, change := range changes {
		k := rrsetKey{name: dns.CanonicalName(change.RRset.Name), rrtype: change.RRset.Type}
		switch change.Op {
		case backend.Add:
			d.added[k] = append(d.added[k], change.RRset.Records...)
			d.ttls[k] = change.RRset.TTL
		case backend.Remove:
			d.removed[k] = append(d.removed[k], change.RRset.Records...)
			if _, ok := d.ttls[k]; !ok {
				d.ttls[k] = change.RRset.TTL
			}
		case backend.Replace, backend.Delete:
		}
	}
	return d
}

// recordChange returns the entries of an Add or a Remove: its EXTEND or
// PRUNE, or, on a server without them, the REPLACE of its RRset, with the
// first change of the RRset.
func (b *Backend) recordChange(zone string, change backend.Change, first, recordOps bool, d *deltas) ([]rrset, error) {
	if recordOps {
		return b.recordEntries(zone, change)
	}
	if !first {
		return nil, nil
	}
	k := rrsetKey{name: dns.CanonicalName(change.RRset.Name), rrtype: change.RRset.Type}
	set, err := b.rebuilt(zone, k, d.removed[k], d.added[k], d.ttls[k])
	if err != nil {
		return nil, err
	}
	return []rrset{set}, nil
}

// recordEntries returns the EXTEND or PRUNE of each record of an Add or a
// Remove. PowerDNS takes one record per entry, and a TTL, which only a new
// RRset takes.
func (b *Backend) recordEntries(zone string, change backend.Change) ([]rrset, error) {
	name, typ := dns.CanonicalName(change.RRset.Name), typeName(change.RRset.Type)
	if change.Op == backend.Add && opaque(change.RRset.Type) {
		return nil, fmt.Errorf("tsigoat cannot write %s records", typ)
	}
	entries := make([]rrset, 0, len(change.RRset.Records))
	for _, rr := range change.RRset.Records {
		entry := rrset{Name: name, Type: typ, TTL: new(change.RRset.TTL)}
		if change.Op == backend.Add {
			entry.ChangeType, entry.Records = "EXTEND", []record{{Content: content(rr)}}
		} else {
			entry.ChangeType, entry.Records = "PRUNE", []record{{Content: b.storedContent(zone, name, change.RRset.Type, rr)}}
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// storedContent returns the content, as the API wrote it, of the record of an
// RRset that holds the data of rr; the content that tsigoat writes when the
// lookup of the name read none.
func (b *Backend) storedContent(zone, name string, rrtype uint16, rr dns.RR) string {
	if raw, ok := rr.(*dns.RFC3597); ok && opaque(rrtype) {
		if data, err := hex.DecodeString(raw.Rdata); err == nil {
			return string(data)
		}
	}
	set, _ := b.seenRRset(zone, name, typeName(rrtype))
	for _, r := range set.records {
		if r.Disabled {
			continue
		}
		if parsed, err := parseContent(name, 0, rrtype, r.Content); err == nil && sameRecord(parsed, rr) {
			return r.Content
		}
	}
	return content(rr)
}

// rebuilt returns, for a server without EXTEND and PRUNE, the REPLACE of an
// RRset that changes by records: the records that the lookup of its name
// read, but those removed, and those added, with the disabled ones; or its
// DELETE when nothing stays.
func (b *Backend) rebuilt(zone string, k rrsetKey, removed, added []dns.RR, ttl uint32) (rrset, error) {
	typ := typeName(k.rrtype)
	seen, exists := b.seenRRset(zone, k.name, typ)
	if exists {
		ttl = seen.ttl
	}
	var records []dns.RR
	for _, r := range seen.records {
		if r.Disabled {
			continue
		}
		parsed, err := parseContent(k.name, ttl, k.rrtype, r.Content)
		if err != nil {
			return rrset{}, err
		}
		if !slices.ContainsFunc(removed, func(rr dns.RR) bool { return sameRecord(parsed, rr) }) {
			records = append(records, parsed)
		}
	}
	for _, rr := range added {
		if !slices.ContainsFunc(records, func(held dns.RR) bool { return sameRecord(held, rr) }) {
			records = append(records, rr)
		}
	}
	set := rrset{Name: k.name, Type: typ, ChangeType: "REPLACE", TTL: new(ttl), Records: []record{}}
	if len(records) > 0 {
		var err error
		set, err = toAPI(backend.Change{Op: backend.Replace, RRset: backend.RRset{Name: k.name, Type: k.rrtype, TTL: ttl, Records: records}})
		if err != nil {
			return rrset{}, err
		}
	}
	b.withDisabled(zone, &set)
	if len(set.Records) == 0 {
		return rrset{Name: k.name, Type: typ, ChangeType: "DELETE", Records: []record{}}, nil
	}
	return set, nil
}

// disabledAgain returns the EXTEND that put back the disabled records that
// the lookup of an RRset read, which PowerDNS drops when EXTEND or PRUNE
// change it, but those that the update enables again.
func (b *Backend) disabledAgain(zone string, k rrsetKey, added []dns.RR, ttl uint32) []rrset {
	typ := typeName(k.rrtype)
	seen, exists := b.seenRRset(zone, k.name, typ)
	if exists {
		ttl = seen.ttl
	}
	var sets []rrset
	for _, r := range seen.records {
		if !r.Disabled || slices.ContainsFunc(added, func(rr dns.RR) bool { return sameContent(k.name, typ, content(rr), r.Content) }) {
			continue
		}
		sets = append(sets, rrset{Name: k.name, Type: typ, TTL: new(ttl), ChangeType: "EXTEND", Records: []record{r}})
	}
	return sets
}

// withDisabled adds to an RRset to replace the disabled records that the last
// lookup of its name read, but those that the RRset enables again.
func (b *Backend) withDisabled(zone string, set *rrset) {
	seen, _ := b.seenRRset(zone, set.Name, set.Type)
	for _, candidate := range seen.records {
		if !candidate.Disabled {
			continue
		}
		enabled := slices.ContainsFunc(set.Records, func(r record) bool {
			return !r.Disabled && sameContent(set.Name, set.Type, r.Content, candidate.Content)
		})
		if !enabled {
			set.Records = append(set.Records, candidate)
		}
	}
}
