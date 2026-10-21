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
	// Apply applies the changes to the zone, all or nothing. A
	// *RejectionError turns the update down before anything changes, such
	// as a record that the provider cannot hold. An *IndeterminateError
	// tells that the outcome is unknown: the zone may hold all of the
	// changes, part of them, or none. Other errors are failures that changed
	// nothing, which the client cannot fix.
	//
	// Add and Remove change the records that they name alone, whatever the
	// RRset holds besides, so that the changes of concurrent updates by other
	// instances survive: a backend applies them on the records as they stand
	// when it writes, not as the update read them.
	Apply(ctx context.Context, zone string, changes []Change) error
}

// RecoveryBudget bounds the work that a backend does past the deadline of an
// update, to establish its outcome or to undo it: reading the records back,
// undoing what it wrote. The server waits for it at shutdown.
const RecoveryBudget = 15 * time.Second

// RecoveryContext returns the context of a recovery past the deadline of
// ctx: it keeps the values of ctx, but not its cancellation, and ends after
// RecoveryBudget.
func RecoveryContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), RecoveryBudget)
}

// IndeterminateError reports a write whose outcome tsigoat could not
// establish, as after a timeout whose effect it could not read back, or a
// recovery that failed: the backend may hold all of the update, part of it,
// or none of it.
type IndeterminateError struct {
	Err error
}

func (e *IndeterminateError) Error() string {
	return "outcome unknown: " + e.Err.Error()
}

func (e *IndeterminateError) Unwrap() error {
	return e.Err
}

// Indeterminate returns err as an *IndeterminateError.
func Indeterminate(err error) error {
	return &IndeterminateError{Err: err}
}

// IsIndeterminate reports whether err tells that the outcome of a write is
// unknown.
func IsIndeterminate(err error) bool {
	_, ok := errors.AsType[*IndeterminateError](err)
	return ok
}

// TTLFloor is implemented by the backends whose provider holds no TTL below
// a minimum: they turn lower TTLs down, and the server raises the lower TTLs
// of an update to the minimum, which it logs.
type TTLFloor interface {
	// MinTTL returns the lowest TTL that the backend writes.
	MinTTL() uint32
}

// Relay evaluates the updates of its zones itself: it checks their
// prerequisites and applies them atomically, as RFC 2136 says.
type Relay interface {
	// Update relays an update of the zone, signed by key, "" when unsigned,
	// and returns the rcode that the client gets. A *RejectionError turns the
	// update down; an *IndeterminateError tells that the server may have
	// applied the update or not; other errors are failures of the relay, of
	// its server or of their configuration, which the client cannot fix.
	Update(ctx context.Context, zone, key string, prerequisites, updates []dns.RR) (int, error)
	// SOA returns the SOA record of the zone.
	SOA(ctx context.Context, zone string) (dns.RR, error)
	// Check checks that the relay reaches the zone, without changing it.
	Check(ctx context.Context, zone string) error
}

// RejectionError is an update that a relay turns down before evaluating it,
// or that a backend turns down before applying it, with the rcode of the
// response and the reason.
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

// ObservedBackend returns a backend that reports its calls to observe: lookup
// and apply. An update that the backend turns down is no error.
func ObservedBackend(b Backend, observe Observer) Backend {
	return &observedBackend{backend: b, observe: observe}
}

type observedBackend struct {
	backend Backend
	observe Observer
}

func (o *observedBackend) Lookup(ctx context.Context, zone, name string) ([]RRset, error) {
	start := time.Now()
	sets, err := o.backend.Lookup(ctx, zone, name)
	o.observe("lookup", start, err)
	return sets, err
}

func (o *observedBackend) Apply(ctx context.Context, zone string, changes []Change) error {
	start := time.Now()
	err := o.backend.Apply(ctx, zone, changes)
	o.observe("apply", start, failure(err))
	return err
}

// failure returns err, unless it turns an update down.
func failure(err error) error {
	if _, rejected := errors.AsType[*RejectionError](err); rejected {
		return nil
	}
	return err
}

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
	o.observe("relay", start, failure(err))
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
	// Add adds the given records to an RRset, but those that it holds
	// already. It creates the RRset with the TTL of the change; an RRset
	// that exists keeps its TTL.
	Add
	// Remove removes the given records from an RRset, which goes with its
	// last record; the records that it does not hold are no error.
	Remove
)

// Change is a change of one RRset of a zone.
type Change struct {
	Op Op
	// RRset holds the new content for Replace, the records to add for Add,
	// the records to remove for Remove, and only the name and the type for
	// Delete.
	RRset RRset
}

// String describes the change for logs, for example
// `replace www.example.org. TXT 60 ["a", "b"]` or
// `remove www.example.org. TXT ["a"]`.
func (c Change) String() string {
	typeName := dns.TypeToString[c.RRset.Type]
	values := make([]string, 0, len(c.RRset.Records))
	for _, rr := range c.RRset.Records {
		values = append(values, RData(rr))
	}
	switch c.Op {
	case Delete:
		return fmt.Sprintf("delete %s %s", c.RRset.Name, typeName)
	case Add:
		return fmt.Sprintf("add %s %s %d [%s]", c.RRset.Name, typeName, c.RRset.TTL, strings.Join(values, ", "))
	case Remove:
		return fmt.Sprintf("remove %s %s [%s]", c.RRset.Name, typeName, strings.Join(values, ", "))
	case Replace:
	}
	return fmt.Sprintf("replace %s %s %d [%s]", c.RRset.Name, typeName, c.RRset.TTL, strings.Join(values, ", "))
}

// Canonical returns a record as its wire format decodes it, which erases
// the variations of its presentation format: the case of hexadecimal
// strings, the escapes of TXT strings, the forms of IPv6 addresses. The
// records of an update come in that form, so that the records that a backend
// reads compare with them only once canonical.
func Canonical(rr dns.RR) (dns.RR, error) {
	buf := make([]byte, dns.Len(rr)+1)
	n, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return nil, fmt.Errorf("encoding %s: %w", rr, err)
	}
	decoded, _, err := dns.UnpackRR(buf[:n], 0)
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", rr, err)
	}
	return decoded, nil
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
