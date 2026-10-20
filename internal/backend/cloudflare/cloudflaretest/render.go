package cloudflaretest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/enix/tsigoat/internal/backend/cloudflare"
	"github.com/enix/tsigoat/internal/backend/hosted"
)

// render checks a new record as Cloudflare does, and returns it as
// Cloudflare stores it: its names in lower case without the final dot, and
// for the types with fields, the content that Cloudflare renders from them.
func render(posted *cloudflare.APIRecord, zoneName string) (cloudflare.APIRecord, error) {
	rec := *posted
	rec.ID, rec.Proxied, rec.Meta = "", false, nil
	rec.Name = strings.ToLower(rec.Name)
	if rec.Name == "@" {
		rec.Name = zoneName
	}
	if strings.HasSuffix(rec.Name, ".") || (rec.Name != zoneName && !strings.HasSuffix(rec.Name, "."+zoneName)) {
		return rec, fail(http.StatusBadRequest, 9000, "DNS name is invalid.")
	}
	if rec.TTL == 0 {
		rec.TTL = 1
	}
	if err := checkTTL(rec.TTL); err != nil {
		return rec, err
	}
	if _, fields := dataFields(rec.Type); fields {
		return renderData(&rec)
	}
	return renderContent(&rec)
}

// renderContent checks a record of a type without fields.
func renderContent(rec *cloudflare.APIRecord) (cloudflare.APIRecord, error) {
	switch rec.Type {
	case "A", typeAAAA:
		return renderAddress(rec)
	case typeCNAME:
		rec.Content = host(rec.Content)
		if rec.Content == rec.Name || rec.Content == "" {
			return *rec, fail(http.StatusBadRequest, 9007, "Content for CNAME record is invalid.")
		}
	case "NS", "PTR":
		rec.Content = host(rec.Content)
	case "MX":
		if rec.Priority == nil {
			return *rec, fail(http.StatusBadRequest, 9104, "priority must be an integer between 0 and 65535.")
		}
		rec.Content = host(rec.Content)
	case "TXT", "OPENPGPKEY":
	default:
		return *rec, fail(http.StatusBadRequest, 9000, "%s is not a valid record type.", rec.Type)
	}
	if rec.Content == "" && rec.Type != "TXT" {
		return *rec, fail(http.StatusBadRequest, 9007, "Content for %s record is invalid.", rec.Type)
	}
	return *rec, nil
}

func renderAddress(rec *cloudflare.APIRecord) (cloudflare.APIRecord, error) {
	address, err := netip.ParseAddr(rec.Content)
	if err != nil || address.Is4() != (rec.Type == "A") {
		return *rec, fail(http.StatusBadRequest, 9005, "Content for %s record must be a valid IP address.", rec.Type)
	}
	rec.Content = address.String()
	return *rec, nil
}

// host returns a name in RDATA as Cloudflare stores it.
func host(name string) string {
	if name == "." {
		return name
	}
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

// renderData decodes the fields of a record, and renders its content.
func renderData(rec *cloudflare.APIRecord) (cloudflare.APIRecord, error) {
	if len(rec.Data) == 0 {
		return *rec, fail(http.StatusBadRequest, 9101, "data is a required field.")
	}
	var d map[string]any
	if err := json.Unmarshal(rec.Data, &d); err != nil {
		return *rec, fail(http.StatusBadRequest, 9207, "Request body is invalid.")
	}
	fields, _ := dataFields(rec.Type)
	for _, field := range fields {
		if _, present := d[field]; !present {
			return *rec, fail(http.StatusBadRequest, 9101, "%s is a required data field.", field)
		}
	}
	switch rec.Type {
	case "SRV":
		// The content of an SRV record leaves out its priority.
		priority := uint16(number(d["priority"]))
		rec.Priority = &priority
		rec.Content = fmt.Sprintf("%v %v %s", number(d["weight"]), number(d["port"]), host(fmt.Sprint(d[targetField])))
	case "URI":
		if rec.Priority == nil {
			return *rec, fail(http.StatusBadRequest, 9104, "priority must be an integer between 0 and 65535.")
		}
		rec.Content = fmt.Sprintf("%v %s", number(d["weight"]), quoted(d[targetField]))
	default:
		rec.Content = renderFields(rec.Type, d)
	}
	return *rec, nil
}

// targetField is the field of the target of the SRV, URI, HTTPS and SVCB
// records.
const targetField = "target"

// renderFields renders the content of the types with fields, but SRV and URI,
// with the hexadecimal strings in upper case, as Cloudflare does.
func renderFields(rrtype string, d map[string]any) string {
	upper := func(field string) string { return strings.ToUpper(fmt.Sprint(d[field])) }
	switch rrtype {
	case "CAA":
		return fmt.Sprintf("%v %s %s", number(d["flags"]), d["tag"], quoted(d["value"]))
	case "DS":
		return fmt.Sprintf("%v %v %v %s", number(d["key_tag"]), number(d["algorithm"]), number(d["digest_type"]), upper("digest"))
	case "SSHFP":
		return fmt.Sprintf("%v %v %s", number(d["algorithm"]), number(d["type"]), upper("fingerprint"))
	case "TLSA", "SMIMEA":
		return fmt.Sprintf("%v %v %v %s", number(d["usage"]), number(d["selector"]), number(d["matching_type"]), upper("certificate"))
	case "HTTPS", "SVCB":
		return strings.TrimSpace(fmt.Sprintf("%v %s %s", number(d["priority"]), d[targetField], d["value"]))
	case "NAPTR":
		return fmt.Sprintf("%v %v %s %s %s %s", number(d["order"]), number(d["preference"]),
			quoted(d["flags"]), quoted(d["service"]), quoted(d["regex"]), d["replacement"])
	default: // LOC
		return fmt.Sprintf("%v %v %.3f %s %v %v %.3f %s %.2f %.2f %.2f %.2f",
			number(d["lat_degrees"]), number(d["lat_minutes"]), number(d["lat_seconds"]), d["lat_direction"],
			number(d["long_degrees"]), number(d["long_minutes"]), number(d["long_seconds"]), d["long_direction"],
			number(d["altitude"]), number(d["size"]), number(d["precision_horz"]), number(d["precision_vert"]))
	}
}

// dataFields returns the fields of the types with fields, and whether the
// type is one.
func dataFields(rrtype string) ([]string, bool) {
	switch rrtype {
	case "SRV":
		return []string{"priority", "weight", "port", targetField}, true
	case "URI":
		return []string{"weight", targetField}, true
	case "CAA":
		return []string{"flags", "tag", "value"}, true
	case "DS":
		return []string{"key_tag", "algorithm", "digest_type", "digest"}, true
	case "SSHFP":
		return []string{"algorithm", "type", "fingerprint"}, true
	case "TLSA", "SMIMEA":
		return []string{"usage", "selector", "matching_type", "certificate"}, true
	case "HTTPS", "SVCB":
		return []string{"priority", targetField, "value"}, true
	case "NAPTR":
		return []string{"order", "preference", "flags", "service", "regex", "replacement"}, true
	case "LOC":
		return []string{
			"lat_degrees", "lat_minutes", "lat_seconds", "lat_direction", "long_degrees", "long_minutes",
			"long_seconds", "long_direction", "altitude", "size", "precision_horz", "precision_vert",
		}, true
	default:
		return nil, false
	}
}

// quoted renders a raw string of decoded JSON as the presentation format
// writes a character-string: in quotes, with its escapes.
func quoted(value any) string {
	s, _ := value.(string)
	return `"` + hosted.Escape(s) + `"`
}

// number returns a number of decoded JSON.
func number(value any) float64 {
	n, _ := value.(float64)
	return n
}
