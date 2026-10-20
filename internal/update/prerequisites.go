package update

import (
	"context"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/zone"
)

// CheckPrerequisites evaluates the prerequisites of a request against the
// view, and returns NOERROR when they all hold or the rcode of the first one
// that fails. The structure was checked by Parse.
//
// RFC 2136 3.2:
//
//	for rr in prerequisites
//	     [...]
//	     if (rr.class == ANY)
//	          if (rr.type == ANY)
//	               if (!zone_name<rr.name>)
//	                    return (NXDOMAIN)
//	          else
//	               if (!zone_rrset<rr.name, rr.type>)
//	                    return (NXRRSET)
//	     if (rr.class == NONE)
//	          if (rr.type == ANY)
//	               if (zone_name<rr.name>)
//	                    return (YXDOMAIN)
//	          else
//	               if (zone_rrset<rr.name, rr.type>)
//	                    return (YXRRSET)
//	     if (rr.class == zclass)
//	          temp<rr.name, rr.type> += rr
//
//	for rrset in temp
//	     if (zone_rrset<rrset.name, rrset.type> != rrset)
//	          return (NXRRSET)
func CheckPrerequisites(ctx context.Context, view *zone.View, req *Request) (int, error) {
	type rrsetKey struct {
		name   string
		rrtype uint16
	}
	var order []rrsetKey
	valueDependent := map[rrsetKey][]dns.RR{}

	for _, rr := range req.Prerequisites {
		h := rr.Header()
		name := dns.CanonicalName(h.Name)
		switch h.Class {
		case dns.ClassANY, dns.ClassNONE:
			present, err := exists(ctx, view, name, h.Rrtype)
			if err != nil {
				return dns.RcodeServerFailure, err
			}
			if rcode := existenceRcode(h.Class, h.Rrtype, present); rcode != dns.RcodeSuccess {
				return rcode, nil
			}
		default:
			k := rrsetKey{name: name, rrtype: h.Rrtype}
			if _, seen := valueDependent[k]; !seen {
				order = append(order, k)
			}
			valueDependent[k] = append(valueDependent[k], rr)
		}
	}

	for _, k := range order {
		current, err := view.RRset(ctx, k.name, k.rrtype)
		if err != nil {
			return dns.RcodeServerFailure, err
		}
		if !zone.SameRecords(current, withName(valueDependent[k], k.name)) {
			return dns.RcodeNXRrset, nil
		}
	}
	return dns.RcodeSuccess, nil
}

// exists reports whether the name owns a record, for type ANY, or whether the
// RRset of the given type exists.
func exists(ctx context.Context, view *zone.View, name string, rrtype uint16) (bool, error) {
	if rrtype == dns.TypeANY {
		return view.NameExists(ctx, name)
	}
	set, err := view.RRset(ctx, name, rrtype)
	return len(set) > 0, err
}

// existenceRcode returns the rcode of a value-independent prerequisite.
func existenceRcode(class, rrtype uint16, present bool) int {
	switch {
	case class == dns.ClassANY && !present && rrtype == dns.TypeANY:
		return dns.RcodeNameError
	case class == dns.ClassANY && !present:
		return dns.RcodeNXRrset
	case class == dns.ClassNONE && present && rrtype == dns.TypeANY:
		return dns.RcodeYXDomain
	case class == dns.ClassNONE && present:
		return dns.RcodeYXRrset
	default:
		return dns.RcodeSuccess
	}
}

// withName returns copies of the records with the canonical owner name, so
// that they compare with the zone records.
func withName(records []dns.RR, name string) []dns.RR {
	copies := make([]dns.RR, len(records))
	for i, rr := range records {
		copies[i] = dns.Copy(rr)
		copies[i].Header().Name = name
	}
	return copies
}
