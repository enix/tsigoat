package powerdns

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
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
	converted := backend.RRset{Name: dns.CanonicalName(set.Name), Type: code}
	if set.TTL != nil {
		converted.TTL = *set.TTL
	}
	for _, r := range set.Records {
		if r.Disabled {
			continue
		}
		rr, err := parseContent(converted.Name, converted.TTL, code, r.Content)
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
		set.TTL = new(change.RRset.TTL)
		set.Records = make([]record, 0, len(change.RRset.Records))
		for _, rr := range change.RRset.Records {
			set.Records = append(set.Records, record{Content: content(rr)})
		}
		return set, nil
	default:
		return rrset{}, fmt.Errorf("unknown operation %d", change.Op)
	}
}

// content returns the content of a record for the API: its RDATA in
// presentation format, as PowerDNS writes it, since PowerDNS refuses content
// that it would write differently. Only SVCB and HTTPS records need care:
// miekg/dns quotes every value of their parameters, PowerDNS none.
func content(rr dns.RR) string {
	switch typed := rr.(type) {
	case *dns.SVCB:
		return svcbContent(typed)
	case *dns.HTTPS:
		return svcbContent(&typed.SVCB)
	default:
		return backend.RData(rr)
	}
}

func svcbContent(rr *dns.SVCB) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(int(rr.Priority)))
	b.WriteString(" ")
	b.WriteString(rr.Target)
	for _, pair := range rr.Value {
		b.WriteString(" ")
		b.WriteString(pair.Key().String())
		switch value := pair.String(); {
		case value == "":
		case strings.ContainsAny(value, " \t\";"):
			b.WriteString(`="` + value + `"`)
		default:
			b.WriteString("=" + value)
		}
	}
	return b.String()
}

// notInExpectedFormat matches the message of PowerDNS about content that it
// would write differently.
var notInExpectedFormat = regexp.MustCompile(`^Record (.+)/([A-Z0-9-]+) '(.*)': Not in expected format \(parsed as '(.*)'\)$`)

// reformat rewrites, in a refused PATCH, the content that PowerDNS would
// write differently, provided its form is the same RDATA. It reports whether
// it rewrote something.
func reformat(err error, sets []rrset) bool {
	apiErr, ok := errors.AsType[*APIError](err)
	if !ok || apiErr.Status != http.StatusUnprocessableEntity {
		return false
	}
	match := notInExpectedFormat.FindStringSubmatch(apiErr.Message)
	if match == nil {
		return false
	}
	name, typeName, sent, parsed := dns.CanonicalName(match[1]), match[2], match[3], match[4]
	for i := range sets {
		set := &sets[i]
		if dns.CanonicalName(set.Name) != name || set.Type != typeName {
			continue
		}
		for j := range set.Records {
			if set.Records[j].Content == sent && sameContent(name, set.Type, sent, parsed) {
				set.Records[j].Content = parsed
				return true
			}
		}
	}
	return false
}

// sameContent reports whether two contents encode the same RDATA.
func sameContent(name, typeName, a, b string) bool {
	code, err := typeCode(typeName)
	if err != nil || opaque(code) {
		return false
	}
	first, errA := parseContent(name, 0, code, a)
	second, errB := parseContent(name, 0, code, b)
	if errA != nil || errB != nil {
		return false
	}
	wireA, errA := wire(first)
	wireB, errB := wire(second)
	return errA == nil && errB == nil && wireA == wireB
}

// wire returns the wire format of a record.
func wire(rr dns.RR) (string, error) {
	buf := make([]byte, dns.Len(rr)+1)
	n, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		return "", fmt.Errorf("encoding %s: %w", rr, err)
	}
	return string(buf[:n]), nil
}
