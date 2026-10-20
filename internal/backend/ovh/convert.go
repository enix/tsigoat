package ovh

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/hosted"
)

// The bounds of the TTLs that OVHcloud holds: it stores 60 for a lower TTL,
// and reads 0 as the default TTL of the zone.
const (
	minTTL = 60
	maxTTL = 86400
)

// apiRecord is a record of the API.
type apiRecord struct {
	ID int64 `json:"id,omitempty"`
	// FieldType is the type: a DNS type, or SPF, DKIM and DMARC, which the
	// name servers serve as TXT records.
	FieldType string `json:"fieldType"`
	// SubDomain is the owner name relative to the zone, "" for the apex.
	SubDomain string `json:"subDomain"`
	// Target is the RDATA in presentation format, with hostnames relative
	// to the zone unless they end with a dot.
	Target string `json:"target"`
	// TTL is the TTL, 0 for the default TTL of the zone.
	TTL uint32 `json:"ttl"`
}

// newLimits returns what OVHcloud holds.
func newLimits() *hosted.Limits {
	return &hosted.Limits{
		Provider: provider,
		Types: []uint16{
			dns.TypeA, dns.TypeAAAA, dns.TypeCAA, dns.TypeCNAME, dns.TypeDNAME, dns.TypeHTTPS, dns.TypeLOC, dns.TypeMX,
			dns.TypeNAPTR, dns.TypeNS, dns.TypePTR, dns.TypeRP, dns.TypeSRV, dns.TypeSSHFP, dns.TypeSVCB, dns.TypeTLSA,
			dns.TypeTXT,
		},
		MinTTL:  minTTL,
		MaxTTL:  maxTTL,
		Content: content,
	}
}

// content returns why OVHcloud cannot hold a record, "" when it can. It
// mangles the quotes and backslashes of TXT strings and the spaces at their
// ends, and holds no empty TXT string: tsigoat keeps the TXT strings and the
// CAA values to printable ASCII without quotes or backslashes, which it
// knows to come back intact.
func content(rr dns.RR) string {
	switch record := rr.(type) {
	case *dns.TXT:
		for _, s := range record.Txt {
			if reason := plain(s); reason != "" {
				return reason
			}
			if s == "" || s[0] == ' ' || s[len(s)-1] == ' ' {
				return "empty strings, and spaces at their ends, do not come back intact"
			}
		}
	case *dns.CAA:
		return plain(record.Value)
	case *dns.NAPTR:
		for _, s := range []string{record.Flags, record.Service, record.Regexp} {
			if reason := plain(s); reason != "" {
				return reason
			}
		}
	}
	return ""
}

// plain returns why a string would not come back intact, "" when it would.
func plain(s string) string {
	for i := range len(s) {
		if c := s[i]; c < ' ' || c > '~' || c == '"' || c == '\\' {
			return "only printable ASCII without quotes and backslashes comes back intact"
		}
	}
	return ""
}

// fromAPI converts a record of a zone, whose default TTL is defaultTTL. It
// returns nil for the records of a type that tsigoat does not know.
func fromAPI(r *apiRecord, zone string, defaultTTL uint32) (dns.RR, error) {
	name := zone
	if r.SubDomain != "" {
		name = dns.CanonicalName(r.SubDomain + "." + zone)
	}
	ttl := r.TTL
	if ttl == 0 {
		ttl = defaultTTL
	}
	header := dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}
	switch r.FieldType {
	case "TXT", "SPF":
		if strings.HasPrefix(r.Target, `"`) {
			break
		}
		// An unquoted target is a single string, as the records written
		// before OVHcloud started to quote them.
		return &dns.TXT{Hdr: header, Txt: hosted.TXTStrings(r.Target)}, nil
	case "DKIM", "DMARC":
		return &dns.TXT{Hdr: header, Txt: hosted.TXTStrings(r.Target)}, nil
	}
	rrtype, known := dns.StringToType[r.FieldType]
	if !known || rrtype == dns.TypeSOA {
		return nil, nil //nolint:nilnil // the caller skips the records of unknown types
	}
	if r.FieldType == "SPF" {
		rrtype = dns.TypeTXT
	}
	// Hostnames without a final dot are relative to the zone.
	text := fmt.Sprintf("%s %d IN %s %s", name, ttl, dns.TypeToString[rrtype], r.Target)
	parser := dns.NewZoneParser(strings.NewReader(text), zone, "")
	rr, ok := parser.Next()
	if err := parser.Err(); err != nil || !ok {
		return nil, fmt.Errorf("parsing the target %q: %w", r.Target, errors.Join(err, errors.New("no record")))
	}
	if rr.Header().Name != name {
		return nil, fmt.Errorf("parsing the target %q: unexpected name %s", r.Target, rr.Header().Name)
	}
	return backend.Canonical(rr)
}

// toAPI converts a record of a zone, of a type that the limits accept, for
// its creation. TXT records come as TXT records, never as the SPF, DKIM and
// DMARC types of OVHcloud, which it validates further.
func toAPI(rr dns.RR, zone string) apiRecord {
	h := rr.Header()
	return apiRecord{
		FieldType: dns.Type(h.Rrtype).String(),
		SubDomain: hosted.Relative(dns.CanonicalName(h.Name), zone),
		Target:    backend.RData(rr),
		TTL:       h.Ttl,
	}
}
