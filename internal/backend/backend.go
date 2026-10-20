// Package backend defines the contract between tsigoat and the DNS providers
// that hold the zones.
//
// A Backend holds zones for the update engine of tsigoat: the engine reads the
// RRsets of the names it touches with Lookup, computes the result of an update
// in memory, then hands the resulting RRset-level changes to Apply in a single
// call, which must be atomic. A Relay evaluates the updates itself, such as a
// name server that implements RFC 2136: tsigoat checks an update and its
// policy, then hands it over whole.
package backend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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

// Relay evaluates the updates of its zones itself: it checks their
// prerequisites and applies them atomically, as RFC 2136 says.
type Relay interface {
	// Update relays an update of the zone, signed by key, "" when unsigned,
	// and returns the rcode that the client gets. A *RejectionError turns the
	// update down; other errors are failures of the relay, of its server or
	// of their configuration, which the client cannot fix.
	Update(ctx context.Context, zone, key string, prerequisites, updates []dns.RR) (int, error)
	// SOA returns the SOA record of the zone.
	SOA(ctx context.Context, zone string) (dns.RR, error)
	// Check checks that the relay reaches the zone, without changing it.
	Check(ctx context.Context, zone string) error
}

// RejectionError is an update that a relay turns down before evaluating it,
// with the rcode of the response and the reason.
type RejectionError struct {
	Rcode  int
	Reason string
}

func (r *RejectionError) Error() string {
	return fmt.Sprintf("%s: %s", dns.RcodeToString[r.Rcode], r.Reason)
}

// Observer is told about the calls to a backend: the operation, when it
// started, and its error.
type Observer func(operation string, start time.Time, err error)

// ObservedRelay returns a relay that reports its calls to observe: relay for
// the updates, lookup for the SOA queries, check for the checks. An update
// that the relay or its server turns down, such as one whose prerequisites
// fail, is no error.
func ObservedRelay(r Relay, observe Observer) Relay {
	return &observedRelay{relay: r, observe: observe}
}

type observedRelay struct {
	relay   Relay
	observe Observer
}

func (o *observedRelay) Update(ctx context.Context, zone, key string, prerequisites, updates []dns.RR) (int, error) {
	start := time.Now()
	rcode, err := o.relay.Update(ctx, zone, key, prerequisites, updates)
	if _, rejected := errors.AsType[*RejectionError](err); rejected {
		o.observe("relay", start, nil)
	} else {
		o.observe("relay", start, err)
	}
	return rcode, err
}

func (o *observedRelay) SOA(ctx context.Context, zone string) (dns.RR, error) {
	start := time.Now()
	soa, err := o.relay.SOA(ctx, zone)
	o.observe("lookup", start, err)
	return soa, err
}

func (o *observedRelay) Check(ctx context.Context, zone string) error {
	start := time.Now()
	err := o.relay.Check(ctx, zone)
	o.observe("check", start, err)
	return err
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
	// The text of a record starts with four tab-terminated fields: name,
	// TTL, class and type. Comparing with the text of the header would not
	// do, as the records of unknown types write their class differently.
	fields := strings.SplitN(rr.String(), "\t", 5)
	if len(fields) < 5 {
		return ""
	}
	return fields[4]
}
