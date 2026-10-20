// Package backend defines the contract between the update engine and the DNS
// providers that hold the zones.
//
// The engine reads the RRsets of the names it touches with Lookup, computes
// the result of an update in memory, then hands the resulting RRset-level
// changes to Apply in a single call, which must be atomic.
package backend

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// ErrZoneNotFound reports a zone that the backend does not hold.
var ErrZoneNotFound = errors.New("zone not found")

// Backend holds zones and applies changes to them.
type Backend interface {
	// Lookup returns every RRset of the zone owned by the canonical name.
	Lookup(ctx context.Context, zone, name string) ([]RRset, error)
	// Apply applies the changes to the zone, all or nothing.
	Apply(ctx context.Context, zone string, changes []Change) error
}

// RRset is a set of records sharing an owner name, a type and a TTL.
type RRset struct {
	// Name is the canonical owner name.
	Name string
	Type uint16
	TTL  uint32
	// Records share the name, the type and the TTL above.
	Records []dns.RR
}

// Op is the operation of a change.
type Op int

// Operations.
const (
	// Replace sets an RRset to the given records, creating it if needed.
	Replace Op = iota + 1
	// Delete removes an RRset.
	Delete
)

// Change is an RRset-level change of a zone.
type Change struct {
	Op Op
	// RRset holds the new content for Replace, only the name and the type
	// for Delete.
	RRset RRset
}

// String describes the change for logs, for example
// `replace www.example.org. TXT 60 ["a", "b"]`.
func (c Change) String() string {
	typeName := dns.TypeToString[c.RRset.Type]
	if c.Op == Delete {
		return fmt.Sprintf("delete %s %s", c.RRset.Name, typeName)
	}
	values := make([]string, 0, len(c.RRset.Records))
	for _, rr := range c.RRset.Records {
		values = append(values, RData(rr))
	}
	return fmt.Sprintf("replace %s %s %d [%s]", c.RRset.Name, typeName, c.RRset.TTL, strings.Join(values, ", "))
}

// RData returns the RDATA of a record in presentation format.
func RData(rr dns.RR) string {
	return strings.TrimPrefix(rr.String(), rr.Header().String())
}
