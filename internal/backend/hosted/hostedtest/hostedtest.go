// Package hostedtest helps simulate the API of a hosted DNS provider in
// tests: a store of zones whose records, in the format of the provider, have
// identifiers, and change in transactions that apply whole or not at all.
package hostedtest

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"
)

// ErrNoZone reports a zone that the store does not hold.
var ErrNoZone = errors.New("no such zone")

// ErrNoRecord reports a record that a zone does not hold.
var ErrNoRecord = errors.New("no such record")

// Store holds zones of records of type R. It is safe for concurrent use.
type Store[R any] struct {
	mu     sync.Mutex
	zones  map[string]map[string]R
	nextID int
}

// NewStore returns an empty store.
func NewStore[R any]() *Store[R] {
	return &Store[R]{zones: map[string]map[string]R{}}
}

// SetZone creates or empties a zone, then adds the records to it.
func (s *Store[R]) SetZone(zone string, records ...R) {
	s.mu.Lock()
	defer s.mu.Unlock()
	content := map[string]R{}
	for _, r := range records {
		content[s.newID()] = r
	}
	s.zones[zone] = content
}

// DeleteZone removes a zone.
func (s *Store[R]) DeleteZone(zone string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.zones, zone)
}

// HasZone reports whether the store holds a zone.
func (s *Store[R]) HasZone(zone string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.zones[zone]
	return ok
}

// Entry is a record with its identifier.
type Entry[R any] struct {
	ID     string
	Record R
}

// Records returns the records of a zone that keep returns true for, in the
// order of their identifiers, which is the order of their creation.
func (s *Store[R]) Records(zone string, keep func(R) bool) ([]Entry[R], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	content, ok := s.zones[zone]
	if !ok {
		return nil, fmt.Errorf("%s: %w", zone, ErrNoZone)
	}
	return entries(content, keep), nil
}

// Update applies change to a zone in a transaction: the zone changes only if
// change returns nil.
func (s *Store[R]) Update(zone string, change func(tx *Tx[R]) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	content, ok := s.zones[zone]
	if !ok {
		return fmt.Errorf("%s: %w", zone, ErrNoZone)
	}
	tx := &Tx[R]{store: s, content: maps.Clone(content)}
	if err := change(tx); err != nil {
		return err
	}
	s.zones[zone] = tx.content
	return nil
}

// newID returns a new identifier. The caller holds the lock.
func (s *Store[R]) newID() string {
	s.nextID++
	return strconv.Itoa(s.nextID)
}

// Tx is a transaction on a zone.
type Tx[R any] struct {
	store   *Store[R]
	content map[string]R
}

// Records returns the records of the zone, as the transaction left it, that
// keep returns true for.
func (tx *Tx[R]) Records(keep func(R) bool) []Entry[R] {
	return entries(tx.content, keep)
}

// Get returns a record.
func (tx *Tx[R]) Get(id string) (R, error) {
	r, ok := tx.content[id]
	if !ok {
		return r, fmt.Errorf("%s: %w", id, ErrNoRecord)
	}
	return r, nil
}

// Create adds a record, and returns its identifier.
func (tx *Tx[R]) Create(r R) string {
	id := tx.store.newID()
	tx.content[id] = r
	return id
}

// Put replaces a record.
func (tx *Tx[R]) Put(id string, r R) error {
	if _, ok := tx.content[id]; !ok {
		return fmt.Errorf("%s: %w", id, ErrNoRecord)
	}
	tx.content[id] = r
	return nil
}

// Delete removes a record.
func (tx *Tx[R]) Delete(id string) error {
	if _, ok := tx.content[id]; !ok {
		return fmt.Errorf("%s: %w", id, ErrNoRecord)
	}
	delete(tx.content, id)
	return nil
}

func entries[R any](content map[string]R, keep func(R) bool) []Entry[R] {
	var list []Entry[R]
	for id, r := range content {
		if keep == nil || keep(r) {
			list = append(list, Entry[R]{ID: id, Record: r})
		}
	}
	slices.SortFunc(list, func(a, b Entry[R]) int {
		x, _ := strconv.Atoi(a.ID)
		y, _ := strconv.Atoi(b.ID)
		return cmp.Compare(x, y)
	})
	return list
}
