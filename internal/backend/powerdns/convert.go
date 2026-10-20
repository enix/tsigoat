package powerdns

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
)

// Types that PowerDNS knows and miekg/dns does not. Their records are kept
// opaque: tsigoat can test and delete them, but not write them.
const (
	typeALIAS uint16 = 65401
	typeLUA   uint16 = 65402
)

// typeCode returns the code of a type name of the API.
func typeCode(name string) (uint16, error) {
	upper := strings.ToUpper(name)
	if code, ok := dns.StringToType[upper]; ok {
		return code, nil
	}
	switch upper {
	case "ALIAS":
		return typeALIAS, nil
	case "LUA":
		return typeLUA, nil
	}
	if digits, ok := strings.CutPrefix(upper, "TYPE"); ok {
		if code, err := strconv.ParseUint(digits, 10, 16); err == nil {
			return uint16(code), nil
		}
	}
	return 0, fmt.Errorf("unknown type %q", name)
}

// typeName returns the name of a type in the API.
func typeName(code uint16) string {
	switch code {
	case typeALIAS:
		return "ALIAS"
	case typeLUA:
		return "LUA"
	default:
		return dns.Type(code).String()
	}
}

func opaque(code uint16) bool {
	return code == typeALIAS || code == typeLUA
}

// fromAPI converts an RRset of the API, leaving out the disabled records.
func fromAPI(set *rrset) (backend.RRset, error) {
	code, err := typeCode(set.Type)
	if err != nil {
		return backend.RRset{}, err
	}
	converted := backend.RRset{Name: dns.CanonicalName(set.Name), Type: code, TTL: set.TTL}
	for _, r := range set.Records {
		if r.Disabled {
			continue
		}
		rr, err := parseContent(converted.Name, set.TTL, code, r.Content)
		if err != nil {
			return backend.RRset{}, err
		}
		converted.Records = append(converted.Records, rr)
	}
	return converted, nil
}

// parseContent parses the content of a record, which is its RDATA in
// presentation format.
func parseContent(name string, ttl uint32, code uint16, content string) (dns.RR, error) {
	if opaque(code) {
		header := dns.RR_Header{Name: name, Rrtype: code, Class: dns.ClassINET, Ttl: ttl}
		return &dns.RFC3597{Hdr: header, Rdata: hex.EncodeToString([]byte(content))}, nil
	}
	rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", name, ttl, dns.Type(code), content))
	if err == nil && rr == nil {
		err = errors.New("no record")
	}
	if err != nil {
		return nil, fmt.Errorf("parsing the content %q: %w", content, err)
	}
	return rr, nil
}

// toAPI converts a change into an RRset of a PATCH request.
func toAPI(change backend.Change) (rrset, error) {
	set := rrset{Name: dns.CanonicalName(change.RRset.Name), Type: typeName(change.RRset.Type)}
	switch change.Op {
	case backend.Delete:
		set.ChangeType = "DELETE"
		return set, nil
	case backend.Replace:
		if opaque(change.RRset.Type) {
			return rrset{}, fmt.Errorf("tsigoat cannot write %s records", set.Type)
		}
		set.ChangeType = "REPLACE"
		set.TTL = change.RRset.TTL
		set.Records = make([]record, 0, len(change.RRset.Records))
		for _, rr := range change.RRset.Records {
			set.Records = append(set.Records, record{Content: backend.RData(rr)})
		}
		return set, nil
	default:
		return rrset{}, fmt.Errorf("unknown operation %d", change.Op)
	}
}
