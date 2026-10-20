package auth

import (
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
}

// NewPolicy returns the policy of a zone.
func NewPolicy(z *config.Zone) (*Policy, error) {
	p := &Policy{unauthenticated: z.AllowUnauthenticated, keys: map[string]bool{}}
	for _, name := range z.Keys {
		p.keys[dns.CanonicalName(name)] = true
	}
	for i, r := range z.Policy {
		compiled := rule{key: dns.CanonicalName(r.Key)}
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

// AllowsUpdate reports whether the identity may update the RRset of the given
// type at name, a canonical name of the zone. The type ANY stands for the
// deletion of every RRset of the name.
func (p *Policy) AllowsUpdate(identity, name string, rrtype uint16) bool {
	if rrtype != dns.TypeSOA && (p.unauthenticated || p.keys[identity]) {
		return true
	}
	for i := range p.rules {
		r := &p.rules[i]
		if r.key == identity && identity != Unauthenticated && r.allowsType(rrtype) && r.matches(name) {
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
	for i := len(pattern) - 1; i >= 0; i-- {
		current := make([]bool, len(name)+1)
		for j := len(name) - 1; j >= 0; j-- {
			switch pattern[i] {
			case "**":
				current[j] = next[j+1] || current[j+1]
			case "*":
				current[j] = next[j+1]
			default:
				current[j] = next[j+1] && pattern[i] == name[j]
			}
		}
		next = current
	}
	return next[0]
}
