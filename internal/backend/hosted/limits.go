package hosted

import (
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
)

// Limits are what a provider holds. Check enforces them before anything is
// written, so that tsigoat turns down what it could only write
// approximately.
type Limits struct {
	// Provider names the provider in the reasons, such as "Cloudflare".
	Provider string
	// Types holds the record types that the provider holds.
	Types []uint16
	// MinTTL and MaxTTL bound the TTLs that the provider holds.
	MinTTL, MaxTTL uint32
	// Content returns why the provider cannot hold a record, "" when it
	// can; every record that the provider types hold is fine when nil.
	Content func(rr dns.RR) string
}

// Check returns a *backend.RejectionError for the first change of zone that
// the provider cannot apply faithfully: a change of the SOA or of the NS
// records of the apex, which the provider manages; a type that it does not
// hold; an owner name other than a host name, with underscores and a leading
// wildcard; a TTL out of its bounds; a content that it cannot hold.
func (l *Limits) Check(zone string, changes []backend.Change) error {
	for i := range changes {
		if reason := l.reason(zone, &changes[i]); reason != "" {
			return &backend.RejectionError{Rcode: dns.RcodeRefused, Reason: reason}
		}
	}
	return nil
}

func (l *Limits) reason(zone string, change *backend.Change) string {
	set := &change.RRset
	typeName := dns.Type(set.Type).String()
	switch {
	case set.Type == dns.TypeSOA:
		return l.Provider + " manages the SOA record"
	case set.Type == dns.TypeNS && dns.CanonicalName(set.Name) == zone:
		return l.Provider + " manages the NS records of the apex"
	case !hostName(set.Name):
		return fmt.Sprintf("%s holds no name like %s: letters, digits, hyphens and underscores only, and a leading wildcard", l.Provider, set.Name)
	case change.Op == backend.Delete || change.Op == backend.Remove:
		// Whatever the provider holds, it may delete.
		return ""
	case !slices.Contains(l.Types, set.Type):
		return fmt.Sprintf("%s holds no %s record", l.Provider, typeName)
	case set.TTL < l.MinTTL:
		return fmt.Sprintf("%s holds no TTL below %d", l.Provider, l.MinTTL)
	case l.MaxTTL > 0 && set.TTL > l.MaxTTL:
		return fmt.Sprintf("%s holds no TTL above %d", l.Provider, l.MaxTTL)
	}
	if l.Content != nil {
		for _, rr := range set.Records {
			if reason := l.Content(rr); reason != "" {
				return fmt.Sprintf("%s holds no %s record like %s: %s", l.Provider, typeName, backend.RData(rr), reason)
			}
		}
	}
	return ""
}

// hostName reports whether a canonical name is made of labels of letters,
// digits, hyphens and underscores, but a leading "*" label.
func hostName(name string) bool {
	labels := dns.SplitDomainName(name)
	for i, label := range labels {
		if i == 0 && label == "*" {
			continue
		}
		if label == "" || strings.IndexFunc(label, func(r rune) bool {
			return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_'
		}) >= 0 {
			return false
		}
	}
	return true
}

// Relative returns a canonical name of zone relative to it: "" for the apex,
// "www" for www.example.org. in example.org.
func Relative(name, zone string) string {
	if name == zone {
		return ""
	}
	return strings.TrimSuffix(name, "."+zone)
}
