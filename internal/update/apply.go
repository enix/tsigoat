package update

import (
	"context"
	"fmt"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/zone"
)

// Apply processes the update section of a request on the view, following
// RFC 2136 3.4.2. Nothing reaches the backend: the caller applies the
// changes of the view afterwards.
//
//	[rr] for rr in updates
//	     if (rr.class == zclass)
//	          [add, see add]
//	     elsif (rr.class == ANY)
//	          [delete RRsets, see deleteRRsets]
//	     elsif (rr.class == NONE)
//	          [delete an RR, see deleteRecord]
//	return (NOERROR)
func Apply(ctx context.Context, view *zone.View, req *Request) error {
	for _, rr := range req.Updates {
		var err error
		switch rr.Header().Class {
		case req.Class:
			err = add(ctx, view, rr)
		case dns.ClassANY:
			err = deleteRRsets(ctx, view, rr)
		case dns.ClassNONE:
			err = deleteRecord(ctx, view, rr, req.Class)
		default:
			err = fmt.Errorf("unexpected class %s", dns.ClassToString[rr.Header().Class])
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// add adds a record to its RRset, RFC 2136 3.4.2.2.
//
//	if (rr.type == CNAME)
//	     if (zone_rrset<rr.name, ~CNAME>)
//	          next [rr]
//	elsif (zone_rrset<rr.name, CNAME>)
//	     next [rr]
//	if (rr.type == SOA)
//	     if (!zone_rrset<rr.name, SOA> ||
//	         zone_rr<rr.name, SOA>.serial > rr.soa.serial)
//	          next [rr]
//	for zrr in zone_rrset<rr.name, rr.type>
//	     if (rr.type == CNAME || rr.type == SOA ||
//	         (rr.type == WKS && rr.proto == zrr.proto &&
//	          rr.address == zrr.address) ||
//	         rr.rdata == zrr.rdata)
//	          zrr = rr
//	          next [rr]
//	zone_rrset<rr.name, rr.type> += rr
//
// Two refinements: the RRSIG and NSEC records that DNSSEC places beside a
// CNAME do not conflict with it (RFC 4035 2.5), and since an RRset has a
// single TTL (RFC 2181 5.2), the added record sets the TTL of its RRset, as
// BIND does.
func add(ctx context.Context, view *zone.View, rr dns.RR) error {
	name := dns.CanonicalName(rr.Header().Name)
	rrtype := rr.Header().Rrtype
	sets, err := view.RRsets(ctx, name)
	if err != nil {
		return err
	}
	if conflictsWithCNAME(sets, rrtype) {
		return nil
	}

	switch rrtype {
	case dns.TypeSOA:
		if !replacesSOA(sets[dns.TypeSOA], rr) {
			return nil
		}
		return view.SetRRset(ctx, name, rrtype, []dns.RR{rr})
	case dns.TypeCNAME:
		return view.SetRRset(ctx, name, rrtype, []dns.RR{rr})
	default:
		return view.SetRRset(ctx, name, rrtype, merge(sets[rrtype], rr))
	}
}

// conflictsWithCNAME reports whether a record of the given type cannot join
// the RRsets of its owner name: a CNAME stands alone, but for the RRSIG and
// NSEC records of DNSSEC.
func conflictsWithCNAME(sets map[uint16][]dns.RR, rrtype uint16) bool {
	if besideCNAME(rrtype) {
		return false
	}
	if rrtype != dns.TypeCNAME {
		_, ok := sets[dns.TypeCNAME]
		return ok
	}
	for existing := range sets {
		if existing != dns.TypeCNAME && !besideCNAME(existing) {
			return true
		}
	}
	return false
}

// replacesSOA reports whether an added SOA record replaces the current one:
// there must be one, and the new serial must be greater.
func replacesSOA(current []dns.RR, rr dns.RR) bool {
	soa, ok := rr.(*dns.SOA)
	if !ok || len(current) == 0 {
		return false
	}
	zoneSOA, ok := current[0].(*dns.SOA)
	return ok && serialGreater(soa.Serial, zoneSOA.Serial)
}

// merge adds a record to an RRset, in place of its duplicate if any, and
// gives the whole RRset the TTL of the record.
func merge(current []dns.RR, rr dns.RR) []dns.RR {
	next := make([]dns.RR, 0, len(current)+1)
	replaced := false
	for _, existing := range current {
		if dns.IsDuplicate(existing, withClass(rr, existing.Header().Class)) {
			next = append(next, rr)
			replaced = true
			continue
		}
		next = append(next, existing)
	}
	if !replaced {
		next = append(next, rr)
	}
	for _, record := range next {
		record.Header().Ttl = rr.Header().Ttl
	}
	return next
}

// deleteRRsets deletes an RRset, or every RRset of a name, RFC 2136 3.4.2.3.
//
//	if (rr.type == ANY)
//	     if (rr.name == zname)
//	          zone_rrset<rr.name, ~(SOA|NS)> = Nil
//	     else
//	          zone_rrset<rr.name, *> = Nil
//	elsif (rr.name == zname &&
//	       (rr.type == SOA || rr.type == NS))
//	     next [rr]
//	else
//	     zone_rrset<rr.name, rr.type> = Nil
func deleteRRsets(ctx context.Context, view *zone.View, rr dns.RR) error {
	name := dns.CanonicalName(rr.Header().Name)
	rrtype := rr.Header().Rrtype
	apex := name == view.Zone()

	if rrtype == dns.TypeANY {
		sets, err := view.RRsets(ctx, name)
		if err != nil {
			return err
		}
		for existing := range sets {
			if apex && (existing == dns.TypeSOA || existing == dns.TypeNS) {
				continue
			}
			if err := view.SetRRset(ctx, name, existing, nil); err != nil {
				return err
			}
		}
		return nil
	}
	if apex && (rrtype == dns.TypeSOA || rrtype == dns.TypeNS) {
		return nil
	}
	return view.SetRRset(ctx, name, rrtype, nil)
}

// deleteRecord deletes one record, RFC 2136 3.4.2.4: "any Zone RR whose
// NAME, TYPE, RDATA and RDLENGTH are equal to the Update RR is deleted,
// unless the NAME is the same as ZNAME and either the TYPE is SOA or the TYPE
// is NS and the matching Zone RR is the only NS remaining in the RRset".
func deleteRecord(ctx context.Context, view *zone.View, rr dns.RR, class uint16) error {
	name := dns.CanonicalName(rr.Header().Name)
	rrtype := rr.Header().Rrtype
	apex := name == view.Zone()
	if apex && rrtype == dns.TypeSOA {
		return nil
	}

	current, err := view.RRset(ctx, name, rrtype)
	if err != nil {
		return err
	}
	target := withClass(rr, class)
	remaining := make([]dns.RR, 0, len(current))
	for _, existing := range current {
		if !dns.IsDuplicate(existing, target) {
			remaining = append(remaining, existing)
		}
	}
	if len(remaining) == len(current) {
		return nil
	}
	if apex && rrtype == dns.TypeNS && len(remaining) == 0 {
		return nil
	}
	return view.SetRRset(ctx, name, rrtype, remaining)
}

// besideCNAME reports the types that DNSSEC places beside a CNAME.
func besideCNAME(rrtype uint16) bool {
	return rrtype == dns.TypeRRSIG || rrtype == dns.TypeNSEC
}

// serialGreater compares SOA serials with the sequence space arithmetic of
// RFC 1982: is a greater than b?
func serialGreater(a, b uint32) bool {
	const half = 1 << 31
	return (a < b && b-a > half) || (a > b && a-b < half)
}

// withClass returns a copy of the record in another class, to compare an
// update record with the zone records.
func withClass(rr dns.RR, class uint16) dns.RR {
	c := dns.Copy(rr)
	c.Header().Class = class
	return c
}
