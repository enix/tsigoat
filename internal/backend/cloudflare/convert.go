package cloudflare

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/hosted"
)

// The bounds of the TTLs that Cloudflare holds; 1 is its automatic TTL, which
// its name servers serve as 300.
const (
	minTTL  = 60
	maxTTL  = 86400
	autoTTL = 1
	// autoTTLServed is the TTL that the name servers serve for autoTTL.
	autoTTLServed = 300
)

// APIRecord is a record of the API. Most types hold their RDATA in Content;
// the types with fields hold them in Data, which Cloudflare renders into
// Content for reading.
type APIRecord struct {
	ID string `json:"id,omitempty"`
	// Name is the owner name, without the final dot.
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Content  string          `json:"content,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
	Priority *uint16         `json:"priority,omitempty"`
	TTL      uint32          `json:"ttl"`
	// Proxied tells that Cloudflare serves its own addresses for the
	// record.
	Proxied bool `json:"proxied,omitempty"`
	Meta    *struct {
		// ReadOnly marks the records that another product of Cloudflare
		// manages, such as Email Routing.
		ReadOnly bool `json:"read_only"`
	} `json:"meta,omitempty"`
}

// newLimits returns what Cloudflare holds.
func newLimits() *hosted.Limits {
	return &hosted.Limits{
		Provider: provider,
		Types: []uint16{
			dns.TypeA, dns.TypeAAAA, dns.TypeCAA, dns.TypeCNAME, dns.TypeDS, dns.TypeHTTPS, dns.TypeLOC, dns.TypeMX,
			dns.TypeNAPTR, dns.TypeNS, dns.TypeOPENPGPKEY, dns.TypePTR, dns.TypeSMIMEA, dns.TypeSRV, dns.TypeSSHFP,
			dns.TypeSVCB, dns.TypeTLSA, dns.TypeTXT, dns.TypeURI,
		},
		MinTTL:  minTTL,
		MaxTTL:  maxTTL,
		Content: content,
	}
}

// content returns why Cloudflare cannot hold a record, "" when it can: it
// neither stores nor serves an empty TXT record, and tsigoat keeps the
// strings of the records to printable ASCII, whose escapes it knows to come
// back intact.
func content(rr dns.RR) string {
	var strs []string
	switch record := rr.(type) {
	case *dns.TXT:
		if len(record.Txt) == 1 && record.Txt[0] == "" {
			return "it serves no empty TXT record"
		}
		strs = record.Txt
	case *dns.NAPTR:
		strs = []string{record.Flags, record.Service, record.Regexp}
	case *dns.CAA:
		strs = []string{record.Value}
	case *dns.URI:
		strs = []string{record.Target}
	}
	for _, s := range strs {
		if !hosted.Printable(s) {
			return "tsigoat keeps the strings of the records to printable ASCII"
		}
	}
	return ""
}

// The fields of the records of the types that have some, as the API names
// them.
type (
	srvData struct {
		Priority uint16 `json:"priority"`
		Weight   uint16 `json:"weight"`
		Port     uint16 `json:"port"`
		Target   string `json:"target"`
	}
	uriData struct {
		Weight uint16 `json:"weight"`
		Target string `json:"target"`
	}
	caaData struct {
		Flags uint8  `json:"flags"`
		Tag   string `json:"tag"`
		Value string `json:"value"`
	}
	dsData struct {
		KeyTag     uint16 `json:"key_tag"`
		Algorithm  uint8  `json:"algorithm"`
		DigestType uint8  `json:"digest_type"`
		Digest     string `json:"digest"`
	}
	svcbData struct {
		Priority uint16 `json:"priority"`
		Target   string `json:"target"`
		Value    string `json:"value"`
	}
	naptrData struct {
		Order       uint16 `json:"order"`
		Preference  uint16 `json:"preference"`
		Flags       string `json:"flags"`
		Service     string `json:"service"`
		Regex       string `json:"regex"`
		Replacement string `json:"replacement"`
	}
	sshfpData struct {
		Algorithm   uint8  `json:"algorithm"`
		Type        uint8  `json:"type"`
		Fingerprint string `json:"fingerprint"`
	}
	tlsaData struct {
		Usage        uint8  `json:"usage"`
		Selector     uint8  `json:"selector"`
		MatchingType uint8  `json:"matching_type"`
		Certificate  string `json:"certificate"`
	}
	locData struct {
		LatDegrees    int     `json:"lat_degrees"`
		LatMinutes    int     `json:"lat_minutes"`
		LatSeconds    float64 `json:"lat_seconds"`
		LatDirection  string  `json:"lat_direction"`
		LongDegrees   int     `json:"long_degrees"`
		LongMinutes   int     `json:"long_minutes"`
		LongSeconds   float64 `json:"long_seconds"`
		LongDirection string  `json:"long_direction"`
		Altitude      float64 `json:"altitude"`
		Size          float64 `json:"size"`
		PrecisionHorz float64 `json:"precision_horz"`
		PrecisionVert float64 `json:"precision_vert"`
	}
)

// FromAPI converts a record of the API. It returns a record without RR for
// the types that tsigoat does not know, such as ALIAS. A proxied record, or
// one that another product of Cloudflare manages, is locked.
func FromAPI(r *APIRecord) (hosted.Record, error) {
	held := hosted.Record{ID: r.ID}
	switch {
	case r.Proxied:
		held.Locked = "Cloudflare proxies " + r.Name + " " + r.Type + ": tsigoat leaves the records that it proxies alone"
	case r.Meta != nil && r.Meta.ReadOnly:
		held.Locked = "another product of Cloudflare manages " + r.Name + " " + r.Type
	}
	rrtype, known := dns.StringToType[r.Type]
	if !known {
		return held, nil
	}
	name := dns.CanonicalName(r.Name)
	ttl := r.TTL
	if ttl == autoTTL {
		ttl = autoTTLServed
	}
	if rrtype == dns.TypeTXT && !strings.HasPrefix(r.Content, `"`) {
		// Unquoted content is a single string, which the name servers split
		// into strings of 255 bytes.
		held.RR = &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: ttl}, Txt: hosted.TXTStrings(r.Content)}
		return held, nil
	}
	rdata, err := rdataOf(r, rrtype)
	if err != nil {
		return held, err
	}
	// Cloudflare drops the final dot of some names in RDATA: they are
	// relative to the root.
	parser := dns.NewZoneParser(strings.NewReader(fmt.Sprintf("%s %d IN %s %s", name, ttl, r.Type, rdata)), ".", "")
	rr, ok := parser.Next()
	if parseErr := parser.Err(); parseErr != nil || !ok {
		return held, fmt.Errorf("parsing %s %s: %w", r.Type, rdata, errors.Join(parseErr, errors.New("no record")))
	}
	if held.RR, err = backend.Canonical(rr); err != nil {
		return held, err
	}
	return held, nil
}

// rdataOf returns the RDATA of a record in presentation format: its content,
// but for the records whose content leaves out a field.
func rdataOf(r *APIRecord, rrtype uint16) (string, error) {
	switch rrtype {
	case dns.TypeMX:
		if r.Priority == nil {
			return "", errors.New("MX record without priority")
		}
		return fmt.Sprintf("%d %s", *r.Priority, absolute(r.Content)), nil
	case dns.TypeSRV:
		var d srvData
		if err := json.Unmarshal(r.Data, &d); err != nil {
			return "", fmt.Errorf("decoding the data of an SRV record: %w", err)
		}
		return fmt.Sprintf("%d %d %d %s", d.Priority, d.Weight, d.Port, absolute(d.Target)), nil
	case dns.TypeURI:
		var d uriData
		if err := json.Unmarshal(r.Data, &d); err != nil || r.Priority == nil {
			return "", fmt.Errorf("decoding the data of a URI record: %w", errors.Join(err, errors.New("no priority")))
		}
		return fmt.Sprintf("%d %d %s", *r.Priority, d.Weight, quote(d.Target)), nil
	case dns.TypeCNAME, dns.TypeNS, dns.TypePTR:
		return absolute(r.Content), nil
	default:
		return r.Content, nil
	}
}

// quote returns a string in quotes, with its quotes and backslashes escaped,
// as the presentation format writes the strings.
func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// absolute returns a name of the API as an absolute name.
func absolute(name string) string {
	return dns.Fqdn(name)
}

// relative returns a name in RDATA as the API takes it, without the final
// dot, but the root.
func relative(name string) string {
	if name == "." {
		return name
	}
	return strings.TrimSuffix(name, ".")
}

// ToAPI converts a record for its creation.
func ToAPI(rr dns.RR) (APIRecord, error) {
	h := rr.Header()
	r := APIRecord{Name: strings.TrimSuffix(dns.CanonicalName(h.Name), "."), Type: dns.TypeToString[h.Rrtype], TTL: h.Ttl}
	if content, priority, ok := contentOf(rr); ok {
		r.Content, r.Priority = content, priority
		return r, nil
	}
	data, priority, err := dataOf(rr)
	if err != nil {
		return APIRecord{}, err
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return APIRecord{}, fmt.Errorf("encoding the data of %s: %w", rr, err)
	}
	r.Data, r.Priority = encoded, priority
	return r, nil
}

// contentOf returns the content of a record of a type without fields, its
// priority for an MX record, and whether its type is one.
func contentOf(rr dns.RR) (content string, priority *uint16, ok bool) {
	switch record := rr.(type) {
	case *dns.A:
		return record.A.String(), nil, true
	case *dns.AAAA:
		return record.AAAA.String(), nil, true
	case *dns.CNAME:
		return relative(record.Target), nil, true
	case *dns.NS:
		return relative(record.Ns), nil, true
	case *dns.PTR:
		return relative(record.Ptr), nil, true
	case *dns.MX:
		return relative(record.Mx), new(record.Preference), true
	case *dns.TXT, *dns.OPENPGPKEY:
		return backend.RData(rr), nil, true
	default:
		return "", nil, false
	}
}

// dataOf returns the fields of a record of a type with fields, and its
// priority for a URI record.
func dataOf(rr dns.RR) (data any, priority *uint16, err error) {
	switch record := rr.(type) {
	case *dns.SRV:
		return srvData{Priority: record.Priority, Weight: record.Weight, Port: record.Port, Target: relative(record.Target)}, nil, nil
	case *dns.URI:
		target, err := hosted.Unescape(record.Target)
		return uriData{Weight: record.Weight, Target: target}, new(record.Priority), err
	case *dns.CAA:
		value, err := hosted.Unescape(record.Value)
		return caaData{Flags: record.Flag, Tag: record.Tag, Value: value}, nil, err
	case *dns.DS:
		return dsData{KeyTag: record.KeyTag, Algorithm: record.Algorithm, DigestType: record.DigestType, Digest: record.Digest}, nil, nil
	case *dns.SVCB:
		return svcbOf(record), nil, nil
	case *dns.HTTPS:
		return svcbOf(&record.SVCB), nil, nil
	case *dns.NAPTR:
		naptr, err := naptrOf(record)
		return naptr, nil, err
	case *dns.SSHFP:
		return sshfpData{Algorithm: record.Algorithm, Type: record.Type, Fingerprint: record.FingerPrint}, nil, nil
	case *dns.TLSA:
		return tlsaData{Usage: record.Usage, Selector: record.Selector, MatchingType: record.MatchingType, Certificate: record.Certificate}, nil, nil
	case *dns.SMIMEA:
		return tlsaData{Usage: record.Usage, Selector: record.Selector, MatchingType: record.MatchingType, Certificate: record.Certificate}, nil, nil
	case *dns.LOC:
		loc, err := locOf(record)
		return loc, nil, err
	default:
		return nil, nil, fmt.Errorf("Cloudflare holds no %s record", dns.Type(rr.Header().Rrtype)) //nolint:staticcheck // ST1005: the name of the provider
	}
}

// naptrOf returns the fields of a NAPTR record: its strings go raw, without
// the escapes of the presentation format, which miekg/dns keeps.
func naptrOf(record *dns.NAPTR) (naptrData, error) {
	var strs [3]string
	for i, s := range []string{record.Flags, record.Service, record.Regexp} {
		raw, err := hosted.Unescape(s)
		if err != nil {
			return naptrData{}, err
		}
		strs[i] = raw
	}
	return naptrData{
		Order: record.Order, Preference: record.Preference, Flags: strs[0],
		Service: strs[1], Regex: strs[2], Replacement: record.Replacement,
	}, nil
}

// svcbOf returns the fields of an SVCB or HTTPS record: its parameters go in
// a string, in presentation format, which miekg/dns writes for each value
// with its escapes.
func svcbOf(record *dns.SVCB) svcbData {
	params := make([]string, 0, len(record.Value))
	for _, pair := range record.Value {
		param := pair.Key().String()
		if value := pair.String(); value != "" {
			param += `="` + value + `"`
		}
		params = append(params, param)
	}
	return svcbData{Priority: record.Priority, Target: record.Target, Value: strings.Join(params, " ")}
}

// locOf returns the fields of a LOC record, from its presentation format:
// "52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m".
func locOf(record *dns.LOC) (locData, error) {
	fields := strings.Fields(backend.RData(record))
	if len(fields) != 12 {
		return locData{}, fmt.Errorf("unexpected LOC record %s", record)
	}
	numbers := make([]float64, 0, 10)
	for _, i := range []int{0, 1, 2, 4, 5, 6, 8, 9, 10, 11} {
		n, err := strconv.ParseFloat(strings.TrimSuffix(fields[i], "m"), 64)
		if err != nil {
			return locData{}, fmt.Errorf("unexpected LOC record %s: %w", record, err)
		}
		numbers = append(numbers, n)
	}
	return locData{
		LatDegrees: int(numbers[0]), LatMinutes: int(numbers[1]), LatSeconds: numbers[2], LatDirection: fields[3],
		LongDegrees: int(numbers[3]), LongMinutes: int(numbers[4]), LongSeconds: numbers[5], LongDirection: fields[7],
		Altitude: numbers[6], Size: numbers[7], PrecisionHorz: numbers[8], PrecisionVert: numbers[9],
	}, nil
}
