package scenario

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// NoKey sends a request unsigned.
const NoKey = "none"

// Request is a DNS message sent to tsigoat.
type Request struct {
	// Key identifies the key that signs the request: DefaultKey when empty,
	// unsigned when NoKey.
	Key string `yaml:"key"`
	// Algorithm signs the request with another TSIG algorithm than the one
	// of the key.
	Algorithm string `yaml:"algorithm"`
	// BadSignature signs the request with a wrong secret.
	BadSignature bool `yaml:"badSignature"`
	// TimeShift moves the signing time of the request, in seconds.
	TimeShift int64 `yaml:"timeShift"`
	// Opcode is "update", the default, "query", or the name of another
	// opcode such as "notify", which sends an otherwise empty message.
	Opcode string `yaml:"opcode"`
	// Query is the question of a query, "<name> <TYPE>" with the name
	// relative to the zone; "@ SOA" by default.
	Query string `yaml:"query"`
	// Zone overrides the zone section with an absolute name.
	Zone string `yaml:"zone"`
	// ZoneCount overrides the number of entries of the zone section.
	ZoneCount *int `yaml:"zoneCount"`
	// ZoneType overrides the type of the zone section entry, SOA otherwise.
	ZoneType string `yaml:"zoneType"`
	// UpperCaseNames sends every owner name of the prerequisite and update
	// sections in upper case.
	UpperCaseNames bool `yaml:"upperCaseNames"`
	// Repeat sends the request Repeat times. "{i}" in the update lines takes
	// the iteration index.
	Repeat int `yaml:"repeat"`
	// Prerequisites, in the syntax of the nsupdate prereq command:
	//
	//	nxdomain <name>
	//	yxdomain <name>
	//	nxrrset <name> <type>
	//	yxrrset <name> <type> [<rdata>]
	//
	// plus "raw <record>" and "rawheader <name> <ttl> <class> <type>" to
	// send records exactly as written.
	Prerequisites []string `yaml:"prerequisites"`
	// Updates, in the syntax of the nsupdate update command:
	//
	//	add <name> <ttl> <class> <type> <rdata>
	//	delete <name> [<type> [<rdata>]]
	//
	// plus "raw" and "rawheader" as for the prerequisites.
	Updates []string `yaml:"updates"`
}

// KeyID returns the identifier of the key that signs the request, or NoKey.
func (r *Request) KeyID() string {
	if r.Key == "" {
		return DefaultKey
	}
	return r.Key
}

// Signer returns the key that signs the request and the algorithm to sign
// with. ok is false for unsigned requests.
func (r *Request) Signer() (key Key, algorithm string, ok bool) {
	if r.KeyID() == NoKey {
		return Key{}, "", false
	}
	key, found := KeyByID(r.KeyID())
	if !found {
		return Key{}, "", false
	}
	algorithm = key.Algorithm
	if r.Algorithm != "" {
		algorithm = dns.Fqdn(strings.ToLower(r.Algorithm))
	}
	return key, algorithm, true
}

// Messages returns the DNS messages of the request for the given zone,
// unsigned. A request with Repeat yields one message per iteration.
func (r *Request) Messages(zone string) ([]*dns.Msg, error) {
	if r.KeyID() != NoKey {
		if _, ok := KeyByID(r.KeyID()); !ok {
			return nil, fmt.Errorf("unknown key %q", r.KeyID())
		}
	}
	count := max(r.Repeat, 1)
	messages := make([]*dns.Msg, 0, count)
	for i := range count {
		m, err := r.message(zone, i)
		if err != nil {
			return nil, err
		}
		messages = append(messages, m)
	}
	return messages, nil
}

func (r *Request) message(zone string, index int) (*dns.Msg, error) {
	target := zone
	if r.Zone != "" {
		target = dns.Fqdn(r.Zone)
	}

	m := new(dns.Msg)
	switch r.Opcode {
	case "", "update":
		m.SetUpdate(target)
	case "query":
		return r.query(zone)
	default:
		opcode, ok := dns.StringToOpcode[strings.ToUpper(r.Opcode)]
		if !ok {
			return nil, fmt.Errorf("unknown opcode %q", r.Opcode)
		}
		m.SetQuestion(target, dns.TypeSOA)
		m.Opcode = opcode
		m.RecursionDesired = false
		return m, nil
	}

	if err := r.shapeZoneSection(m); err != nil {
		return nil, err
	}

	for _, line := range r.Prerequisites {
		rr, err := prerequisite(line, zone)
		if err != nil {
			return nil, fmt.Errorf("prerequisite %q: %w", line, err)
		}
		m.Answer = append(m.Answer, rr)
	}
	for _, line := range r.Updates {
		line = strings.ReplaceAll(line, "{i}", strconv.Itoa(index))
		rr, err := update(line, zone)
		if err != nil {
			return nil, fmt.Errorf("update %q: %w", line, err)
		}
		m.Ns = append(m.Ns, rr)
	}

	if r.UpperCaseNames {
		for _, rr := range append(m.Answer, m.Ns...) {
			rr.Header().Name = strings.ToUpper(rr.Header().Name)
		}
	}
	return m, nil
}

// query returns the message of a query.
func (r *Request) query(zone string) (*dns.Msg, error) {
	question := r.Query
	if question == "" {
		question = "@ SOA"
	}
	name, typeName := cut(question)
	rrtype, ok := dns.StringToType[strings.ToUpper(typeName)]
	if name == "" || !ok {
		return nil, fmt.Errorf("invalid query %q: expected <name> <TYPE>", question)
	}
	m := new(dns.Msg)
	m.SetQuestion(absolute(name, zone), rrtype)
	m.RecursionDesired = false
	return m, nil
}

func (r *Request) shapeZoneSection(m *dns.Msg) error {
	if r.ZoneType != "" {
		qtype, ok := dns.StringToType[strings.ToUpper(r.ZoneType)]
		if !ok {
			return fmt.Errorf("unknown zone type %q", r.ZoneType)
		}
		m.Question[0].Qtype = qtype
	}
	if r.ZoneCount != nil {
		count := *r.ZoneCount
		if count < 0 {
			return fmt.Errorf("negative zone count %d", count)
		}
		question := m.Question[0]
		m.Question = make([]dns.Question, count)
		for i := range m.Question {
			m.Question[i] = question
		}
	}
	return nil
}

func prerequisite(line, zone string) (dns.RR, error) {
	verb, rest := cut(line)
	switch verb {
	case "nxdomain", "yxdomain":
		name, extra := cut(rest)
		if name == "" || extra != "" {
			return nil, fmt.Errorf("%s takes a name", verb)
		}
		class := uint16(dns.ClassNONE)
		if verb == "yxdomain" {
			class = dns.ClassANY
		}
		return header(absolute(name, zone), dns.TypeANY, class, 0), nil
	case "nxrrset", "yxrrset":
		name, tail := cut(rest)
		typeName, rdata := cut(tail)
		if name == "" || typeName == "" {
			return nil, fmt.Errorf("%s takes a name and a type", verb)
		}
		if rdata != "" {
			if verb == "nxrrset" {
				return nil, errors.New("nxrrset takes no rdata")
			}
			// Value-dependent: the RRset must exist with exactly these RRs.
			return parseRR(fmt.Sprintf("%s 0 IN %s %s", name, typeName, rdata), zone)
		}
		rrtype, ok := dns.StringToType[strings.ToUpper(typeName)]
		if !ok {
			return nil, fmt.Errorf("unknown type %q", typeName)
		}
		class := uint16(dns.ClassNONE)
		if verb == "yxrrset" {
			class = dns.ClassANY
		}
		return header(absolute(name, zone), rrtype, class, 0), nil
	default:
		return raw(verb, rest, zone)
	}
}

func update(line, zone string) (dns.RR, error) {
	verb, rest := cut(line)
	switch verb {
	case "add":
		return parseRR(rest, zone)
	case "delete":
		name, tail := cut(rest)
		typeName, rdata := cut(tail)
		switch {
		case name == "":
			return nil, errors.New("delete takes a name")
		case typeName == "":
			return header(absolute(name, zone), dns.TypeANY, dns.ClassANY, 0), nil
		case rdata == "":
			rrtype, ok := dns.StringToType[strings.ToUpper(typeName)]
			if !ok {
				return nil, fmt.Errorf("unknown type %q", typeName)
			}
			return header(absolute(name, zone), rrtype, dns.ClassANY, 0), nil
		default:
			rr, err := parseRR(fmt.Sprintf("%s 0 IN %s %s", name, typeName, rdata), zone)
			if err != nil {
				return nil, err
			}
			rr.Header().Class = dns.ClassNONE
			return rr, nil
		}
	default:
		return raw(verb, rest, zone)
	}
}

// raw handles the "raw" and "rawheader" verbs shared by both sections.
func raw(verb, rest, zone string) (dns.RR, error) {
	switch verb {
	case "raw":
		return parseRR(rest, zone)
	case "rawheader":
		fields := strings.Fields(rest)
		if len(fields) != 4 {
			return nil, errors.New("rawheader takes a name, a TTL, a class and a type")
		}
		ttl, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid TTL %q: %w", fields[1], err)
		}
		class, ok := dns.StringToClass[strings.ToUpper(fields[2])]
		if !ok {
			return nil, fmt.Errorf("unknown class %q", fields[2])
		}
		rrtype, ok := dns.StringToType[strings.ToUpper(fields[3])]
		if !ok {
			return nil, fmt.Errorf("unknown type %q", fields[3])
		}
		return header(absolute(fields[0], zone), rrtype, class, uint32(ttl)), nil
	default:
		return nil, fmt.Errorf("unknown verb %q", verb)
	}
}

// header returns an RR without RDATA, as used by the metavalues of RFC 2136.
func header(name string, rrtype, class uint16, ttl uint32) dns.RR {
	return &dns.ANY{Hdr: dns.RR_Header{Name: name, Rrtype: rrtype, Class: class, Ttl: ttl}}
}

// absolute resolves a name relative to the zone; "@" is the zone apex.
func absolute(name, zone string) string {
	switch {
	case name == "@":
		return zone
	case dns.IsFqdn(name):
		return name
	default:
		return name + "." + zone
	}
}

// cut splits off the first whitespace-separated word.
func cut(s string) (head, tail string) {
	s = strings.TrimSpace(s)
	head, tail, _ = strings.Cut(s, " ")
	return head, strings.TrimSpace(tail)
}
