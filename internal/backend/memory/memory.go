// Package memory is an in-memory backend, for tests and dry runs.
package memory

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
)

type rrsetKey struct {
	name   string
	rrtype uint16
}

// Backend holds zones in memory. It is safe for concurrent use.
type Backend struct {
	mu       sync.Mutex
	zones    map[string]map[rrsetKey]backend.RRset
	applyErr error
	applied  int
}

var _ backend.Backend = (*Backend)(nil)

// New returns an empty backend.
func New() *Backend {
	return &Backend{zones: map[string]map[rrsetKey]backend.RRset{}}
}

// SetZone creates or resets a zone with the given records. Records of the
// same RRset take the TTL of the first one.
func (b *Backend) SetZone(zone string, records ...dns.RR) {
	b.mu.Lock()
	defer b.mu.Unlock()

	content := map[rrsetKey]backend.RRset{}
	for _, rr := range records {
		h := rr.Header()
		k := rrsetKey{name: dns.CanonicalName(h.Name), rrtype: h.Rrtype}
		set, ok := content[k]
		if !ok {
			set = backend.RRset{Name: k.name, Type: k.rrtype, TTL: h.Ttl}
		}
		set.Records = append(set.Records, dns.Copy(rr))
		content[k] = set
	}
	b.zones[dns.CanonicalName(zone)] = normalized(content)
}

// DeleteZone removes a zone.
func (b *Backend) DeleteZone(zone string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.zones, dns.CanonicalName(zone))
}

// Records returns the records of a zone, sorted by name, type and RDATA.
func (b *Backend) Records(zone string) ([]dns.RR, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	content, ok := b.zones[dns.CanonicalName(zone)]
	if !ok {
		return nil, fmt.Errorf("%s: %w", zone, backend.ErrZoneNotFound)
	}
	var records []dns.RR
	for _, set := range content {
		records = append(records, copyRecords(set.Records)...)
	}
	slices.SortFunc(records, func(a, b dns.RR) int {
		return cmp.Or(
			cmp.Compare(a.Header().Name, b.Header().Name),
			cmp.Compare(a.Header().Rrtype, b.Header().Rrtype),
			cmp.Compare(a.String(), b.String()),
		)
	})
	return records, nil
}

// FailApply makes every following Apply fail with err, until called with nil.
func (b *Backend) FailApply(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.applyErr = err
}

// Applied returns the number of successful Apply calls.
func (b *Backend) Applied() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.applied
}

// Lookup implements backend.Backend.
func (b *Backend) Lookup(_ context.Context, zone, name string) ([]backend.RRset, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	content, ok := b.zones[dns.CanonicalName(zone)]
	if !ok {
		return nil, fmt.Errorf("%s: %w", zone, backend.ErrZoneNotFound)
	}
	name = dns.CanonicalName(name)
	var sets []backend.RRset
	for k, set := range content {
		if k.name == name {
			set.Records = copyRecords(set.Records)
			sets = append(sets, set)
		}
	}
	slices.SortFunc(sets, func(a, b backend.RRset) int { return cmp.Compare(a.Type, b.Type) })
	return sets, nil
}

// Apply implements backend.Backend: the changes apply all together or not at
// all.
func (b *Backend) Apply(_ context.Context, zone string, changes []backend.Change) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.applyErr != nil {
		return b.applyErr
	}
	zone = dns.CanonicalName(zone)
	content, ok := b.zones[zone]
	if !ok {
		return fmt.Errorf("%s: %w", zone, backend.ErrZoneNotFound)
	}

	next := maps.Clone(content)
	for _, change := range changes {
		set := change.RRset
		if !dns.IsSubDomain(zone, set.Name) {
			return fmt.Errorf("%s is outside zone %s", set.Name, zone)
		}
		k := rrsetKey{name: dns.CanonicalName(set.Name), rrtype: set.Type}
		switch change.Op {
		case backend.Replace:
			if len(set.Records) == 0 {
				return fmt.Errorf("replacing %s %s with no record", set.Name, dns.TypeToString[set.Type])
			}
			set.Records = copyRecords(set.Records)
			next[k] = set
		case backend.Delete:
			delete(next, k)
		default:
			return fmt.Errorf("unknown operation %d", change.Op)
		}
	}
	b.zones[zone] = normalized(next)
	b.applied++
	return nil
}

// normalized gives every record the canonical name and the TTL of its RRset.
func normalized(content map[rrsetKey]backend.RRset) map[rrsetKey]backend.RRset {
	for k, set := range content {
		for _, rr := range set.Records {
			rr.Header().Name = k.name
			rr.Header().Ttl = set.TTL
		}
		content[k] = set
	}
	return content
}

func copyRecords(records []dns.RR) []dns.RR {
	copies := make([]dns.RR, len(records))
	for i, rr := range records {
		copies[i] = dns.Copy(rr)
	}
	return copies
}
