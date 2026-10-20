// Package update implements the processing of DNS UPDATE messages defined by
// RFC 2136, on top of a zone.View. It performs no I/O of its own: the view
// reads from the backend, and the caller applies the resulting changes.
package update

import (
	"fmt"
	"slices"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
)

// MaxRecords bounds the records of the prerequisite and update sections of
// a message, so that a client cannot make tsigoat process unbounded work.
const MaxRecords = 256

// Request is a DNS UPDATE message whose structure has been checked.
type Request struct {
	// Zone is the canonical name of the zone section.
	Zone string
	// Class is the class of the zone section.
	Class uint16
	// Prerequisites and Updates are the records of the prerequisite and
	// update sections, as received.
	Prerequisites []dns.RR
	Updates       []dns.RR
}

// Error is a request that the engine rejects, with the rcode of the
// response.
type Error struct {
	Rcode int
	// Reason explains the rejection, for the logs.
	Reason string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", dns.RcodeToString[e.Rcode], e.Reason)
}

func reject(rcode int, format string, args ...any) *Error {
	return &Error{Rcode: rcode, Reason: fmt.Sprintf(format, args...)}
}

// ParseZone checks the zone section and returns its canonical name and its
// class. It fails with FORMERR.
//
// RFC 2136 3.1.1:
//
//	if (zcount != 1 || ztype != SOA)
//	     return (FORMERR)
//
// The zone class must also be a data class: ANY and NONE have a meaning of
// their own in the other sections.
func ParseZone(m *dns.Msg) (zone string, class uint16, err error) {
	if len(m.Question) != 1 {
		return "", 0, reject(dns.RcodeFormatError, "the zone section holds %d entries instead of one", len(m.Question))
	}
	q := m.Question[0]
	if q.Qtype != dns.TypeSOA {
		return "", 0, reject(dns.RcodeFormatError, "the zone section entry has type %s instead of SOA", dns.Type(q.Qtype))
	}
	if q.Qclass == dns.ClassANY || q.Qclass == dns.ClassNONE {
		return "", 0, reject(dns.RcodeFormatError, "the zone section entry has class %s", dns.Class(q.Qclass))
	}
	return dns.CanonicalName(q.Name), q.Qclass, nil
}

// Parse checks the prerequisite section (RFC 2136 3.2, structure only) and
// the update section (3.4.1, prescan) of a message whose zone section names
// zone. served lists the canonical names of every zone tsigoat serves, to
// find the zone a record belongs to. It returns the request, or an *Error
// about the first problem.
func Parse(m *dns.Msg, zone string, class uint16, served []string) (*Request, error) {
	if count := len(m.Answer) + len(m.Ns); count > MaxRecords {
		return nil, reject(dns.RcodeRefused, "%d records, more than the %d allowed", count, MaxRecords)
	}
	for _, rr := range m.Answer {
		if err := checkPrerequisite(rr, zone, class, served); err != nil {
			return nil, err
		}
	}
	for _, rr := range m.Ns {
		if err := checkUpdate(rr, zone, class, served); err != nil {
			return nil, err
		}
	}
	return &Request{Zone: zone, Class: class, Prerequisites: m.Answer, Updates: m.Ns}, nil
}

// checkPrerequisite performs the structural checks of RFC 2136 3.2.1; the
// evaluation itself waits for the authorization check.
//
//	for rr in prerequisites
//	     if (rr.ttl != 0)
//	          return (FORMERR)
//	     if (zone_of(rr.name) != ZNAME)
//	          return (NOTZONE);
//	     if (rr.class == ANY)
//	          if (rr.rdlength != 0)
//	               return (FORMERR)
//	          [...]
//	     if (rr.class == NONE)
//	          if (rr.rdlength != 0)
//	               return (FORMERR)
//	          [...]
//	     if (rr.class == zclass)
//	          temp<rr.name, rr.type> += rr
//	     else
//	          return (FORMERR)
func checkPrerequisite(rr dns.RR, zone string, class uint16, served []string) error {
	h := rr.Header()
	if h.Ttl != 0 {
		return reject(dns.RcodeFormatError, "prerequisite %s has a TTL", Describe(rr))
	}
	if ZoneOf(h.Name, served) != zone {
		return reject(dns.RcodeNotZone, "prerequisite %s is outside zone %s", Describe(rr), zone)
	}
	switch h.Class {
	case dns.ClassANY, dns.ClassNONE:
		if h.Rdlength != 0 {
			return reject(dns.RcodeFormatError, "prerequisite %s has RDATA", Describe(rr))
		}
	case class:
		// A value-dependent prerequisite names actual records.
		if h.Rrtype == dns.TypeANY || isMetaType(h.Rrtype) {
			return reject(dns.RcodeFormatError, "prerequisite %s names a meta type", Describe(rr))
		}
	default:
		return reject(dns.RcodeFormatError, "prerequisite %s has an invalid class", Describe(rr))
	}
	return nil
}

// checkUpdate performs the prescan of RFC 2136 3.4.1.
//
//	[rr] for rr in updates
//	     if (zone_of(rr.name) != ZNAME)
//	          return (NOTZONE);
//	     if (rr.class == zclass)
//	          if (rr.type & ANY|AXFR|MAILA|MAILB)
//	               return (FORMERR)
//	     elsif (rr.class == ANY)
//	          if (rr.ttl != 0 || rr.rdlength != 0
//	              || rr.type & AXFR|MAILA|MAILB)
//	               return (FORMERR)
//	     elsif (rr.class == NONE)
//	          if (rr.ttl != 0 || rr.type & ANY|AXFR|MAILA|MAILB)
//	               return (FORMERR)
//	     else
//	          return (FORMERR)
//
// The other meta types (OPT, TSIG, TKEY, IXFR) cannot be stored either, and
// are rejected the same way.
func checkUpdate(rr dns.RR, zone string, class uint16, served []string) error {
	h := rr.Header()
	if ZoneOf(h.Name, served) != zone {
		return reject(dns.RcodeNotZone, "update %s is outside zone %s", Describe(rr), zone)
	}
	switch h.Class {
	case class:
		if h.Rrtype == dns.TypeANY || isMetaType(h.Rrtype) {
			return reject(dns.RcodeFormatError, "update %s adds a meta type", Describe(rr))
		}
	case dns.ClassANY:
		if h.Ttl != 0 || h.Rdlength != 0 || isMetaType(h.Rrtype) {
			return reject(dns.RcodeFormatError, "update %s deletes RRsets with a TTL, RDATA or a meta type", Describe(rr))
		}
	case dns.ClassNONE:
		if h.Ttl != 0 || h.Rrtype == dns.TypeANY || isMetaType(h.Rrtype) {
			return reject(dns.RcodeFormatError, "update %s deletes a record with a TTL or a meta type", Describe(rr))
		}
	default:
		return reject(dns.RcodeFormatError, "update %s has an invalid class", Describe(rr))
	}
	return nil
}

// Describe names a record in messages: owner name, class and type.
func Describe(rr dns.RR) string {
	h := rr.Header()
	return fmt.Sprintf("%s %s %s", h.Name, dns.Class(h.Class), dns.Type(h.Rrtype))
}

// Operation describes a record of the update section as nsupdate writes it:
// "add" with the record, "delete" with the name, then the type and the RDATA
// when the deletion names them.
func Operation(rr dns.RR) string {
	h := rr.Header()
	switch h.Class {
	case dns.ClassANY:
		if h.Rrtype == dns.TypeANY {
			return "delete " + h.Name
		}
		return fmt.Sprintf("delete %s %s", h.Name, dns.Type(h.Rrtype))
	case dns.ClassNONE:
		return fmt.Sprintf("delete %s %s %s", h.Name, dns.Type(h.Rrtype), backend.RData(rr))
	default:
		return fmt.Sprintf("add %s %d %s %s", h.Name, h.Ttl, dns.Type(h.Rrtype), backend.RData(rr))
	}
}

// isMetaType reports the types that only exist in messages, ANY aside.
func isMetaType(rrtype uint16) bool {
	switch rrtype {
	case dns.TypeAXFR, dns.TypeIXFR, dns.TypeMAILA, dns.TypeMAILB,
		dns.TypeOPT, dns.TypeTSIG, dns.TypeTKEY:
		return true
	default:
		return false
	}
}

// ZoneOf returns the most specific of the served zones that contains name,
// or "" when none does.
func ZoneOf(name string, served []string) string {
	name = dns.CanonicalName(name)
	best := ""
	for _, zone := range served {
		if dns.IsSubDomain(zone, name) && dns.CountLabel(zone) > dns.CountLabel(best) {
			best = zone
		}
	}
	if best == "" && slices.Contains(served, ".") {
		return "."
	}
	return best
}
