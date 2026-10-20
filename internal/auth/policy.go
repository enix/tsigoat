package auth

import (
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/config"
)

// Unauthenticated is the identity of unsigned requests.
const Unauthenticated = ""

// Policy decides which updates each identity may make in a zone. An identity
// is the canonical name of the key that signed the request, or
// Unauthenticated.
//
// Updates of the SOA are refused unless a rule names the SOA type
// explicitly: the backend maintains the serial.
type Policy struct {
	unauthenticated bool
	// keys may update every RRset but the SOA.
	keys  map[string]bool
	rules []rule
}

type rule struct {
	key string
	// names holds the patterns as label lists, see match.
	names [][]string
	// types allowed; nil allows every type but SOA.
	types []uint16
	// maxTTL, content and maxRecords constrain the records that an update
	// adds under the rule; maxTTL and maxRecords are no bound when zero.
	maxTTL     uint32
	content    config.Content
	maxRecords int
}

// NewPolicy returns the policy of a zone.
func NewPolicy(z *config.Zone) (*Policy, error) {
	p := &Policy{unauthenticated: z.AllowUnauthenticated, keys: map[string]bool{}}
	for _, name := range z.Keys {
		p.keys[dns.CanonicalName(name)] = true
	}
	for i, r := range z.Policy {
		compiled := rule{key: dns.CanonicalName(r.Key), maxTTL: r.MaxTTL, content: r.Content, maxRecords: r.MaxRecords}
		for _, pattern := range r.Names {
			compiled.names = append(compiled.names, labels(dns.CanonicalName(pattern)))
		}
		for _, name := range r.Types {
			rrtype, ok := dns.StringToType[strings.ToUpper(name)]
			if !ok {
				return nil, fmt.Errorf("zone %s, rule %d: unknown type %q", z.Name, i, name)
			}
			compiled.types = append(compiled.types, rrtype)
		}
		p.rules = append(p.rules, compiled)
	}
	return p, nil
}

// Admits reports whether the identity may update anything in the zone.
func (p *Policy) Admits(identity string) bool {
	if p.unauthenticated || p.keys[identity] {
		return true
	}
	return identity != Unauthenticated && slices.ContainsFunc(p.rules, func(r rule) bool { return r.key == identity })
}

// Authorize returns why the policy refuses a request of the identity, or "":
// every record of the update section must be allowed, the records that it
// adds within the constraints of a rule, and every name of the prerequisite
// section updatable by the identity. class is the class of the zone.
func (p *Policy) Authorize(identity string, class uint16, prerequisites, updates []dns.RR) string {
	// added counts the records that the update adds under each rule.
	added := make([]int, len(p.rules))
	for _, rr := range updates {
		allowed, constraint := p.authorizeUpdate(identity, class, rr, added)
		switch {
		case allowed:
		case constraint != "":
			return "the policy does not allow update " + describe(rr) + ": " + constraint
		default:
			return "the policy does not allow update " + describe(rr)
		}
	}
	for i := range p.rules {
		if r := &p.rules[i]; r.maxRecords > 0 && added[i] > r.maxRecords {
			return fmt.Sprintf("the update adds %d records under a rule of key %s, more than the %d that it allows",
				added[i], r.key, r.maxRecords)
		}
	}
	for _, rr := range prerequisites {
		if !p.AllowsName(identity, dns.CanonicalName(rr.Header().Name)) {
			return "the policy does not allow prerequisite " + describe(rr)
		}
	}
	return ""
}

// authorizeUpdate tells whether the policy allows a record of the update
// section, and counts the records that the update adds under each rule. An
// addition goes to the first rule that allows it, constraints included;
// when none does, constraint tells why the first rule that names it refuses
// it.
func (p *Policy) authorizeUpdate(identity string, class uint16, rr dns.RR, added []int) (allowed bool, constraint string) {
	h := rr.Header()
	name := dns.CanonicalName(h.Name)
	switch {
	case h.Rrtype == dns.TypeSOA && h.Class != class:
		// RFC 2136 ignores the deletion of the SOA, which needs no right on
		// the SOA itself.
		return p.AllowsName(identity, name), ""
	case h.Class != class:
		return p.AllowsUpdate(identity, name, h.Rrtype), ""
	case h.Rrtype != dns.TypeSOA && (p.unauthenticated || p.keys[identity]):
		return true, ""
	}
	for i := range p.rules {
		r := &p.rules[i]
		if !r.covers(identity, name, h.Rrtype) {
			continue
		}
		broken := r.brokenConstraint(rr)
		if broken == "" {
			added[i]++
			return true, ""
		}
		constraint = cmp.Or(constraint, broken)
	}
	return false, constraint
}

// AllowsUpdate reports whether the identity may update the RRset of the given
// type at name, a canonical name of the zone. The type ANY stands for the
// deletion of every RRset of the name.
func (p *Policy) AllowsUpdate(identity, name string, rrtype uint16) bool {
	if rrtype != dns.TypeSOA && (p.unauthenticated || p.keys[identity]) {
		return true
	}
	for i := range p.rules {
		if p.rules[i].covers(identity, name, rrtype) {
			return true
		}
	}
	return false
}

// AllowsName reports whether the identity may update at least one RRset of
// name, which entitles it to test the name in prerequisites.
func (p *Policy) AllowsName(identity, name string) bool {
	if p.unauthenticated || p.keys[identity] {
		return true
	}
	for i := range p.rules {
		r := &p.rules[i]
		if r.key == identity && identity != Unauthenticated && r.matches(name) {
			return true
		}
	}
	return false
}

// covers reports whether the rule lets the identity update the RRset of the
// given type at name.
func (r *rule) covers(identity, name string, rrtype uint16) bool {
	return r.key == identity && identity != Unauthenticated && r.allowsType(rrtype) && r.matches(name)
}

// brokenConstraint returns the constraint of the rule that a record to add
// breaks, or "".
func (r *rule) brokenConstraint(rr dns.RR) string {
	if ttl := rr.Header().Ttl; r.maxTTL > 0 && ttl > r.maxTTL {
		return fmt.Sprintf("TTL %d is above %d", ttl, r.maxTTL)
	}
	if r.content == config.ACMEContent && !isACMEChallengeValue(rr) {
		return "not the value of an ACME challenge, a base64url SHA-256 digest alone"
	}
	return ""
}

// isACMEChallengeValue reports whether a record is the TXT record of an ACME
// DNS-01 challenge: one string, the base64url encoding of the SHA-256 digest
// of a key authorization (RFC 8555 8.4).
func isACMEChallengeValue(rr dns.RR) bool {
	txt, ok := rr.(*dns.TXT)
	if !ok || len(txt.Txt) != 1 {
		return false
	}
	digest, err := base64.RawURLEncoding.Strict().DecodeString(txt.Txt[0])
	return err == nil && len(digest) == sha256.Size
}

// describe names a record in messages: owner name, class and type.
func describe(rr dns.RR) string {
	h := rr.Header()
	return fmt.Sprintf("%s %s %s", h.Name, dns.Class(h.Class), dns.Type(h.Rrtype))
}

func (r *rule) allowsType(rrtype uint16) bool {
	if r.types == nil {
		return rrtype != dns.TypeSOA
	}
	return slices.Contains(r.types, rrtype)
}

func (r *rule) matches(name string) bool {
	nameLabels := labels(dns.CanonicalName(name))
	return slices.ContainsFunc(r.names, func(pattern []string) bool { return match(pattern, nameLabels) })
}

// labels splits a name into its labels, from the leftmost one.
func labels(name string) []string {
	return dns.SplitDomainName(name)
}

// match reports whether the labels of a name match a pattern, where a "*"
// label matches exactly one label and a "**" label matches one or more. It
// runs in O(len(pattern) × len(name)), whatever the pattern.
func match(pattern, name []string) bool {
	// next[j] tells whether the pattern labels after the current one match
	// name[j:].
	next := make([]bool, len(name)+1)
	next[len(name)] = true
	for _, patternLabel := range slices.Backward(pattern) {
		current := make([]bool, len(name)+1)
		for j, nameLabel := range slices.Backward(name) {
			switch patternLabel {
			case "**":
				current[j] = next[j+1] || current[j+1]
			case "*":
				current[j] = next[j+1]
			default:
				current[j] = next[j+1] && patternLabel == nameLabel
			}
		}
		next = current
	}
	return next[0]
}
