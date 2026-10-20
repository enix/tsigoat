// Package update implements the processing of DNS UPDATE messages defined by
// RFC 2136, on top of a zone.View. It performs no I/O of its own: the view
// reads from the backend, and the caller applies the resulting changes.
package update

import (
	"slices"

	"github.com/miekg/dns"
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

// ParseZone checks the zone section and returns its canonical name and its
// class, or FORMERR.
//
// RFC 2136 3.1.1:
//
//	if (zcount != 1 || ztype != SOA)
//	     return (FORMERR)
//
// The zone class must also be a data class: ANY and NONE have a meaning of
// their own in the other sections.
func ParseZone(m *dns.Msg) (zone string, class uint16, rcode int) {
	if len(m.Question) != 1 || m.Question[0].Qtype != dns.TypeSOA {
		return "", 0, dns.RcodeFormatError
	}
	q := m.Question[0]
	if q.Qclass == dns.ClassANY || q.Qclass == dns.ClassNONE {
		return "", 0, dns.RcodeFormatError
	}
	return dns.CanonicalName(q.Name), q.Qclass, dns.RcodeSuccess
}

// Parse checks the prerequisite section (RFC 2136 3.2, structure only) and
// the update section (3.4.1, prescan) of a message whose zone section names
// zone. served lists the canonical names of every zone tsigoat serves, to
// find the zone a record belongs to. It returns the request, or the rcode of
// the first problem.
func Parse(m *dns.Msg, zone string, class uint16, served []string) (req *Request, rcode int) {
	if len(m.Answer)+len(m.Ns) > MaxRecords {
		return nil, dns.RcodeRefused
	}
	for _, rr := range m.Answer {
		if rcode := checkPrerequisite(rr, zone, class, served); rcode != dns.RcodeSuccess {
			return nil, rcode
		}
	}
	for _, rr := range m.Ns {
		if rcode := checkUpdate(rr, zone, class, served); rcode != dns.RcodeSuccess {
			return nil, rcode
		}
	}
	return &Request{Zone: zone, Class: class, Prerequisites: m.Answer, Updates: m.Ns}, dns.RcodeSuccess
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
func checkPrerequisite(rr dns.RR, zone string, class uint16, served []string) int {
	h := rr.Header()
	if h.Ttl != 0 {
		return dns.RcodeFormatError
	}
	if zoneOf(h.Name, served) != zone {
		return dns.RcodeNotZone
	}
	switch h.Class {
	case dns.ClassANY, dns.ClassNONE:
		if h.Rdlength != 0 {
			return dns.RcodeFormatError
		}
	case class:
		// A value-dependent prerequisite names actual records.
		if h.Rrtype == dns.TypeANY || isMetaType(h.Rrtype) {
			return dns.RcodeFormatError
		}
	default:
		return dns.RcodeFormatError
	}
	return dns.RcodeSuccess
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
func checkUpdate(rr dns.RR, zone string, class uint16, served []string) int {
	h := rr.Header()
	if zoneOf(h.Name, served) != zone {
		return dns.RcodeNotZone
	}
	switch h.Class {
	case class:
		if h.Rrtype == dns.TypeANY || isMetaType(h.Rrtype) {
			return dns.RcodeFormatError
		}
	case dns.ClassANY:
		if h.Ttl != 0 || h.Rdlength != 0 || isMetaType(h.Rrtype) {
			return dns.RcodeFormatError
		}
	case dns.ClassNONE:
		if h.Ttl != 0 || h.Rrtype == dns.TypeANY || isMetaType(h.Rrtype) {
			return dns.RcodeFormatError
		}
	default:
		return dns.RcodeFormatError
	}
	return dns.RcodeSuccess
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

// zoneOf returns the most specific served zone that contains name, or "".
func zoneOf(name string, served []string) string {
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
