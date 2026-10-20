// Package hosted holds what the backends of hosted DNS providers share. Such
// providers store records one by one, each with an identifier, where tsigoat
// thinks in RRsets: this package groups the records of a name into RRsets,
// and turns an RRset change into the records to create, delete or retime. It
// also checks the changes against the limits of a provider before anything
// is written, and calls the HTTP APIs, with retries on rate limiting.
package hosted

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
)

// Record is a record held by a provider.
type Record struct {
	// ID identifies the record at the provider.
	ID string
	// RR is the record, with its own TTL.
	RR dns.RR
	// Locked tells why tsigoat must leave the record alone, such as a
	// record whose provider serves something else than its data; "" when
	// tsigoat may change it.
	Locked string
}

// Locked returns why tsigoat must leave alone the RRset of a change, ""
// when it may change it: the reason of the first locked record among the
// current records of the RRset.
func Locked(current []Record) string {
	for _, r := range current {
		if r.Locked != "" {
			return r.Locked
		}
	}
	return ""
}

// Printable reports whether a character-string, as miekg/dns holds it with
// the escapes of the presentation format, holds printable ASCII alone: no
// decimal escape such as \195, which stands for another byte, whose handling
// varies across the providers.
func Printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			if i+3 < len(s) && isDigits(s[i+1:i+4]) {
				return false
			}
			i++
		}
	}
	return true
}

// maxString is the length of a character-string of a TXT record.
const maxString = 255

// TXTStrings returns the character-strings of a TXT record whose text a
// provider holds as one unquoted string, as the name servers serve it: in
// strings of 255 bytes, which miekg/dns holds with the escapes of the
// presentation format.
func TXTStrings(text string) []string {
	strs := make([]string, 0, len(text)/maxString+1)
	for {
		chunk := text[:min(len(text), maxString)]
		strs = append(strs, Escape(chunk))
		text = text[len(chunk):]
		if text == "" {
			return strs
		}
	}
}

// Escape escapes the quotes, the backslashes and the bytes outside printable
// ASCII of a raw character-string, as miekg/dns holds them and as the
// presentation format writes them within quotes.
func Escape(s string) string {
	var b strings.Builder
	for i := range len(s) {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < ' ' || c > '~':
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Unescape returns the raw bytes of a character-string as miekg/dns holds it,
// with the escapes of the presentation format: \DDD for a byte, \X for a
// character X.
func Unescape(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		switch {
		case i+3 < len(s) && isDigits(s[i+1:i+4]):
			n, err := strconv.ParseUint(s[i+1:i+4], 10, 8)
			if err != nil {
				return "", fmt.Errorf("invalid escape \\%s in %q", s[i+1:i+4], s)
			}
			b.WriteByte(byte(n))
			i += 3
		case i+1 < len(s):
			b.WriteByte(s[i+1])
			i++
		default:
			return "", fmt.Errorf("unfinished escape in %q", s)
		}
	}
	return b.String(), nil
}

func isDigits(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }) < 0
}

// RRsets groups records of one name into RRsets, sorted by type. An RRset
// takes the lowest TTL of its records, the one that resolvers keep when the
// TTLs of an RRset differ (RFC 2181 5.2), and its records take it too.
func RRsets(records []Record) []backend.RRset {
	var sets []backend.RRset
	for _, r := range records {
		h := r.RR.Header()
		i := slices.IndexFunc(sets, func(set backend.RRset) bool { return set.Type == h.Rrtype })
		if i < 0 {
			sets = append(sets, backend.RRset{Name: dns.CanonicalName(h.Name), Type: h.Rrtype, TTL: h.Ttl})
			i = len(sets) - 1
		}
		sets[i].TTL = min(sets[i].TTL, h.Ttl)
		sets[i].Records = append(sets[i].Records, dns.Copy(r.RR))
	}
	for i := range sets {
		for _, rr := range sets[i].Records {
			rr.Header().Ttl = sets[i].TTL
		}
	}
	slices.SortFunc(sets, func(a, b backend.RRset) int { return cmp.Compare(a.Type, b.Type) })
	return sets
}

// Steps turn the records of an RRset at a provider into the content of a
// change.
type Steps struct {
	// Delete holds the records to delete.
	Delete []Record
	// Create holds the records to create, with the TTL of the RRset.
	Create []dns.RR
	// Retime holds the records to keep whose TTL changes: their RR carries
	// the TTL of the RRset.
	Retime []Record
}

// Empty reports whether the steps change nothing.
func (s *Steps) Empty() bool {
	return len(s.Delete) == 0 && len(s.Create) == 0 && len(s.Retime) == 0
}

// Diff returns the steps that turn current, the records of the RRset of a
// change at the provider, into the content of the change. A record that the
// RRset keeps stays, and only changes its TTL if needed; a duplicate goes.
func Diff(current []Record, change *backend.Change) Steps {
	var wanted []Record
	if change.Op == backend.Replace {
		for _, rr := range change.RRset.Records {
			record := dns.Copy(rr)
			record.Header().Ttl = change.RRset.TTL
			wanted = append(wanted, Record{RR: record})
		}
	}
	return Restore(current, wanted)
}

// Restore returns the steps that turn current, the records of an RRset at the
// provider, into wanted, records with their own TTLs, such as the records of
// the RRset before an update that failed. A record that wanted holds stays,
// and only gets the TTL of wanted if needed; the others go.
func Restore(current, wanted []Record) Steps {
	var steps Steps
	kept := make([]bool, len(current))
	for _, w := range wanted {
		i := slices.IndexFunc(current, func(r Record) bool { return dns.IsDuplicate(r.RR, w.RR) })
		for i >= 0 && kept[i] {
			next := slices.IndexFunc(current[i+1:], func(r Record) bool { return dns.IsDuplicate(r.RR, w.RR) })
			if next < 0 {
				i = -1
				break
			}
			i += next + 1
		}
		if i < 0 {
			steps.Create = append(steps.Create, dns.Copy(w.RR))
			continue
		}
		kept[i] = true
		if ttl := w.RR.Header().Ttl; current[i].RR.Header().Ttl != ttl {
			retimed := dns.Copy(current[i].RR)
			retimed.Header().Ttl = ttl
			steps.Retime = append(steps.Retime, Record{ID: current[i].ID, RR: retimed})
		}
	}
	for i, r := range current {
		if !kept[i] {
			steps.Delete = append(steps.Delete, r)
		}
	}
	return steps
}

// OfType returns the records of a type.
func OfType(records []Record, rrtype uint16) []Record {
	return slices.DeleteFunc(slices.Clone(records), func(r Record) bool { return r.RR.Header().Rrtype != rrtype })
}

// Settled reports whether the current records, by canonical name, are as
// the changes want them.
func Settled(current map[string][]Record, changes []backend.Change) bool {
	for i := range changes {
		change := &changes[i]
		steps := Diff(OfType(current[dns.CanonicalName(change.RRset.Name)], change.RRset.Type), change)
		if !steps.Empty() {
			return false
		}
	}
	return true
}
