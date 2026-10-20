package update

import (
	"context"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/zone"
)

// CheckPrerequisites evaluates the prerequisites of a request against the
// view. It returns nil when they all hold, an *Error about the first one
// that fails, or the error of the backend. The structure was checked by
// Parse.
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
func CheckPrerequisites(ctx context.Context, view *zone.View, req *Request) error {
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
				return err
			}
			if err := existence(rr, present); err != nil {
				return err
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
			return err
		}
		if !zone.SameRecords(current, withName(valueDependent[k], k.name)) {
			return reject(dns.RcodeNXRrset, "prerequisite failed: RRset %s %s differs", k.name, dns.Type(k.rrtype))
		}
	}
	return nil
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

// existence evaluates a value-independent prerequisite.
func existence(rr dns.RR, present bool) error {
	h := rr.Header()
	name, rrtype := dns.CanonicalName(h.Name), dns.Type(h.Rrtype)
	switch {
	case h.Class == dns.ClassANY && !present && h.Rrtype == dns.TypeANY:
		return reject(dns.RcodeNameError, "prerequisite failed: name %s is not in use", name)
	case h.Class == dns.ClassANY && !present:
		return reject(dns.RcodeNXRrset, "prerequisite failed: RRset %s %s does not exist", name, rrtype)
	case h.Class == dns.ClassNONE && present && h.Rrtype == dns.TypeANY:
		return reject(dns.RcodeYXDomain, "prerequisite failed: name %s is in use", name)
	case h.Class == dns.ClassNONE && present:
		return reject(dns.RcodeYXRrset, "prerequisite failed: RRset %s %s exists", name, rrtype)
	default:
		return nil
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
