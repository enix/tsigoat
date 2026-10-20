package scaleway

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

// The bounds of the TTLs that Scaleway holds, and the TTL that it gives the NS
// records whatever their TTL.
const (
	minTTL = 60
	maxTTL = 2592000
	nsTTL  = 1800
	// maxString is the length of a character-string of a TXT record.
	maxString = 255
)

// APIRecord is a record of the API.
type APIRecord struct {
	ID string `json:"id,omitempty"`
	// Name is the owner name relative to the zone, "" for the apex.
	Name string `json:"name"`
	Type string `json:"type"`
	// Data is the RDATA in presentation format.
	Data string `json:"data"`
	// Priority is the priority of the MX and SRV records, which Data holds
	// too; tsigoat writes 0.
	Priority uint32 `json:"priority"`
	TTL      uint32 `json:"ttl"`
	// The settings of the dynamic records, which answer according to the
	// client or to health checks, with Data as their default.
	GeoIPConfig       json.RawMessage `json:"geo_ip_config,omitempty"`
	HTTPServiceConfig json.RawMessage `json:"http_service_config,omitempty"`
	WeightedConfig    json.RawMessage `json:"weighted_config,omitempty"`
	ViewConfig        json.RawMessage `json:"view_config,omitempty"`
}

// dynamic reports whether a record is dynamic.
func (r *APIRecord) dynamic() bool {
	for _, config := range [][]byte{r.GeoIPConfig, r.HTTPServiceConfig, r.WeightedConfig, r.ViewConfig} {
		if len(config) > 0 && string(config) != "null" {
			return true
		}
	}
	return false
}

// newLimits returns what Scaleway holds, of what tsigoat checked that it
// keeps intact.
func newLimits() *hosted.Limits {
	return &hosted.Limits{
		Provider: provider,
		Types: []uint16{
			dns.TypeA, dns.TypeAAAA, dns.TypeCAA, dns.TypeCNAME, dns.TypeDNAME, dns.TypeHTTPS, dns.TypeMX,
			dns.TypeNAPTR, dns.TypeNS, dns.TypeSRV, dns.TypeSSHFP, dns.TypeSVCB, dns.TypeTLSA, dns.TypeTXT,
		},
		MinTTL:  minTTL,
		MaxTTL:  maxTTL,
		Content: content,
	}
}

// content returns why Scaleway cannot hold a record, "" when it can.
func content(rr dns.RR) string {
	switch record := rr.(type) {
	case *dns.TXT:
		return txtContent(record.Txt)
	case *dns.CAA:
		return plainContent(record.Value)
	case *dns.NAPTR:
		return plainContent(record.Flags, record.Service, record.Regexp)
	case *dns.SVCB:
		return svcbContent(record)
	case *dns.HTTPS:
		return svcbContent(&record.SVCB)
	case *dns.NS:
		if record.Hdr.Ttl < nsTTL {
			return fmt.Sprintf("it gives NS records a TTL of %d at least", nsTTL)
		}
	}
	return ""
}

// plainContent returns why Scaleway may not keep strings intact, "" when it
// keeps them: tsigoat did not check that it keeps quotes, backslashes, or
// bytes outside printable ASCII.
func plainContent(strs ...string) string {
	for _, s := range strs {
		if strings.ContainsAny(s, `"\`) || !hosted.Printable(s) {
			return "it keeps printable ASCII alone intact, without quotes and backslashes"
		}
	}
	return ""
}

// txtContent returns why Scaleway cannot hold the strings of a TXT record, ""
// when it can. It stores a TXT record as a single string, which it serves in
// strings of 255 bytes; it mangles the quotes, the backslashes and the spaces
// at the ends of the string. An empty string would vanish from the joined
// string, so that every string must hold something, and all but the last 255
// bytes.
func txtContent(strs []string) string {
	if reason := plainContent(strs...); reason != "" {
		return reason
	}
	for i, s := range strs {
		switch {
		case s == "":
			return "it holds no empty TXT string"
		case i < len(strs)-1 && len(s) != maxString:
			return "it holds a TXT record as a single string, which it splits every 255 bytes"
		}
	}
	if text := strings.Join(strs, ""); text[0] == ' ' || text[len(text)-1] == ' ' {
		return "it trims the spaces at the ends of a TXT record"
	}
	return ""
}

// svcbContent returns why Scaleway cannot hold an SVCB or HTTPS record, ""
// when it can: it takes the values of the parameters unquoted.
func svcbContent(record *dns.SVCB) string {
	for _, pair := range record.Value {
		if strings.ContainsAny(pair.String(), " \t\"\\") {
			return "it takes the values of the parameters unquoted"
		}
	}
	return ""
}

// FromAPI converts a record of a zone. It returns a record without RR for the
// types that tsigoat does not know, such as ALIAS. A dynamic record is
// locked: its data is only its default answer.
func FromAPI(r *APIRecord, zone string) (hosted.Record, error) {
	held := hosted.Record{ID: r.ID}
	if r.dynamic() {
		held.Locked = fmt.Sprintf("%s %s is a dynamic record of Scaleway, whose answers depend on the client: tsigoat leaves it alone",
			ownerName(r.Name, zone), r.Type)
	}
	rrtype, known := dns.StringToType[r.Type]
	if !known || rrtype == dns.TypeSOA {
		return held, nil
	}
	owner := ownerName(r.Name, zone)
	// Hostnames without a final dot are relative to the zone.
	text := fmt.Sprintf("%s %d IN %s %s", owner, r.TTL, r.Type, r.Data)
	parser := dns.NewZoneParser(strings.NewReader(text), zone, "")
	rr, ok := parser.Next()
	if err := parser.Err(); err != nil || !ok {
		return held, fmt.Errorf("parsing %s %s: %w", r.Type, r.Data, errors.Join(err, errors.New("no record")))
	}
	canonical, err := backend.Canonical(rr)
	if err != nil {
		return held, err
	}
	held.RR = canonical
	return held, nil
}

// ownerName returns the canonical owner name of a name of the API.
func ownerName(relative, zone string) string {
	if relative == "" || relative == "@" {
		return zone
	}
	return dns.CanonicalName(relative + "." + zone)
}

// ToAPI converts a record of a zone, which the limits accept, for its
// creation.
func ToAPI(rr dns.RR, zone string) APIRecord {
	h := rr.Header()
	r := APIRecord{
		Name: hosted.Relative(dns.CanonicalName(h.Name), zone),
		Type: dns.Type(h.Rrtype).String(),
		Data: backend.RData(rr),
		TTL:  h.Ttl,
	}
	switch record := rr.(type) {
	case *dns.TXT:
		// A single string, which Scaleway splits every 255 bytes.
		r.Data = `"` + strings.Join(record.Txt, "") + `"`
	case *dns.SVCB:
		r.Data = svcbData(record)
	case *dns.HTTPS:
		r.Data = svcbData(&record.SVCB)
	}
	return r
}

// svcbData returns the RDATA of an SVCB or HTTPS record with the values of
// its parameters unquoted.
func svcbData(record *dns.SVCB) string {
	fields := make([]string, 0, 2+len(record.Value))
	fields = append(fields, strconv.Itoa(int(record.Priority)), record.Target)
	for _, pair := range record.Value {
		field := pair.Key().String()
		if value := pair.String(); value != "" {
			field += "=" + value
		}
		fields = append(fields, field)
	}
	return strings.Join(fields, " ")
}
