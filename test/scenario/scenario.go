// Package scenario loads the declarative test scenarios embedded under
// scenarios/ and turns them into DNS messages.
//
// A scenario describes a zone, the requests sent to tsigoat and the expected
// outcome. The same scenarios drive the end-to-end tests against a real
// backend and, later, the unit tests of the update engine.
package scenario

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/miekg/dns"
	"go.yaml.in/yaml/v3"
)

//go:embed scenarios
var files embed.FS

// labelPattern is the shape of a scenario name component, which becomes a
// DNS label of the scenario zone.
var labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Scenario is a zone, one or more requests sent to tsigoat, and the expected
// outcome.
type Scenario struct {
	// Name is the file path under scenarios/, without extension, for example
	// "prerequisites/nxdomain-holds".
	Name string `yaml:"-"`
	// Description says what the scenario checks.
	Description string `yaml:"description"`
	// Refs lists the RFC sections and the defect identifiers the scenario
	// covers.
	Refs []string `yaml:"refs"`
	// KnownDefect names the defect that currently makes the scenario fail.
	// The end-to-end runner reports such a failure as skipped, and fails
	// when the scenario passes, so that the marker goes away with the fix.
	KnownDefect string `yaml:"knownDefect"`
	// Zone describes the zone before the requests.
	Zone Zone `yaml:"zone"`
	// Requests are sent in order, or all at once when Parallel is set.
	Requests []Request `yaml:"requests"`
	// Parallel sends every request at the same time.
	Parallel bool `yaml:"parallel"`
	// Expect is the expected outcome.
	Expect Expect `yaml:"expect"`
}

// Zone describes the zone of a scenario.
type Zone struct {
	// Records are added before the requests, in zone file syntax with names
	// relative to the zone apex. The SOA and the apex NS come with the zone.
	Records []string `yaml:"records"`
	// Unauthenticated zones accept unsigned updates.
	Unauthenticated bool `yaml:"unauthenticated"`
	// Keys lists the identifiers of the keys allowed to update the whole
	// zone; every configured test key when both Keys and Policy are empty.
	Keys []string `yaml:"keys"`
	// Policy grants narrower rights.
	Policy []Rule `yaml:"policy"`
}

// Rule is a policy rule of a scenario zone.
type Rule struct {
	// Key is the identifier of a test key.
	Key string `yaml:"key"`
	// Names are name patterns relative to the zone, "@" for the apex.
	Names []string `yaml:"names"`
	// Types are record types; every type but SOA when empty.
	Types []string `yaml:"types"`
}

// Expect is the expected outcome of a scenario.
type Expect struct {
	// Rcode of every response; NOERROR when empty.
	Rcode string `yaml:"rcode"`
	// TSIGError is the error carried by the TSIG record of every response.
	TSIGError string `yaml:"tsigError"`
	// SignedResponse requires a valid TSIG signature on every response.
	SignedResponse bool `yaml:"signedResponse"`
	// Records is the zone content after the requests, without the SOA, in
	// zone file syntax. The apex NS is implied unless listed. When absent,
	// the zone must be left unchanged.
	Records *[]string `yaml:"records"`
	// Authoritative requires the AA flag on every response.
	Authoritative bool `yaml:"authoritative"`
	// Answer and Authority list the records of these sections of every
	// response as "<owner> <TYPE>", with owner names relative to the zone
	// ("@" for the apex). They are not checked when absent.
	Answer    *[]string `yaml:"answer"`
	Authority *[]string `yaml:"authority"`
}

// All loads every scenario, in lexical order of their names.
func All() ([]Scenario, error) {
	var scenarios []Scenario
	err := fs.WalkDir(files, "scenarios", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || path.Ext(name) != ".yaml" {
			return nil
		}
		s, err := load(name)
		if err != nil {
			return err
		}
		scenarios = append(scenarios, s)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("loading scenarios: %w", err)
	}
	return scenarios, nil
}

func load(name string) (Scenario, error) {
	data, err := files.ReadFile(name)
	if err != nil {
		return Scenario{}, fmt.Errorf("reading %s: %w", name, err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var s Scenario
	if err := decoder.Decode(&s); err != nil {
		return Scenario{}, fmt.Errorf("decoding %s: %w", name, err)
	}
	s.Name = strings.TrimSuffix(strings.TrimPrefix(name, "scenarios/"), ".yaml")

	if err := s.validate(); err != nil {
		return Scenario{}, fmt.Errorf("scenario %s: %w", s.Name, err)
	}
	return s, nil
}

func (s *Scenario) validate() error {
	errs := s.validateShape()
	errs = append(errs, s.validateSyntax()...)
	return errors.Join(errs...)
}

// validateShape checks the fields that need no parsing.
func (s *Scenario) validateShape() []error {
	var errs []error
	for label := range strings.SplitSeq(s.Name, "/") {
		if !labelPattern.MatchString(label) {
			errs = append(errs, fmt.Errorf("name component %q is not a valid DNS label", label))
		}
	}
	if s.Description == "" {
		errs = append(errs, errors.New("missing description"))
	}
	if len(s.Requests) == 0 {
		errs = append(errs, errors.New("no request"))
	}
	for _, rcode := range []string{s.Expect.Rcode, s.Expect.TSIGError} {
		if _, ok := dns.StringToRcode[rcode]; rcode != "" && !ok {
			errs = append(errs, fmt.Errorf("unknown rcode %q", rcode))
		}
	}
	return append(errs, s.Zone.validate()...)
}

func (z *Zone) validate() []error {
	var errs []error
	for _, id := range z.Keys {
		if _, ok := KeyByID(id); !ok {
			errs = append(errs, fmt.Errorf("unknown zone key %q", id))
		}
	}
	for i, rule := range z.Policy {
		if _, ok := KeyByID(rule.Key); !ok {
			errs = append(errs, fmt.Errorf("policy rule %d: unknown key %q", i, rule.Key))
		}
		if len(rule.Names) == 0 {
			errs = append(errs, fmt.Errorf("policy rule %d: no name", i))
		}
	}
	if z.Unauthenticated && (len(z.Keys) > 0 || len(z.Policy) > 0) {
		errs = append(errs, errors.New("an unauthenticated zone cannot list keys or rules"))
	}
	return errs
}

// validateSyntax builds every message and parses every record against a
// sample zone, so that syntax errors surface when loading rather than in the
// middle of a test.
func (s *Scenario) validateSyntax() []error {
	const sampleZone = "sample.test."
	var errs []error
	if _, err := ParseRecords(s.Zone.Records, sampleZone); err != nil {
		errs = append(errs, fmt.Errorf("zone records: %w", err))
	}
	if s.Expect.Records != nil {
		if _, err := ParseRecords(*s.Expect.Records, sampleZone); err != nil {
			errs = append(errs, fmt.Errorf("expected records: %w", err))
		}
	}
	for i := range s.Requests {
		if _, err := s.Requests[i].Messages(sampleZone); err != nil {
			errs = append(errs, fmt.Errorf("request %d: %w", i, err))
		}
	}
	return errs
}

// ZoneName returns the zone of the scenario under the given parent domain:
// "prerequisites/nxdomain-holds" under "e2e.test." becomes
// "nxdomain-holds.prerequisites.e2e.test.".
func (s *Scenario) ZoneName(parent string) string {
	labels := strings.Split(s.Name, "/")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, ".") + "." + dns.Fqdn(parent)
}

// ExpectedRcode returns the expected rcode of every response.
func (s *Scenario) ExpectedRcode() string {
	if s.Expect.Rcode == "" {
		return dns.RcodeToString[dns.RcodeSuccess]
	}
	return s.Expect.Rcode
}

// ParseRecords parses records written in zone file syntax, with names
// relative to the given zone.
func ParseRecords(lines []string, zone string) ([]dns.RR, error) {
	records := make([]dns.RR, 0, len(lines))
	for _, line := range lines {
		rr, err := parseRR(line, zone)
		if err != nil {
			return nil, err
		}
		records = append(records, rr)
	}
	return records, nil
}

func parseRR(text, zone string) (dns.RR, error) {
	parser := dns.NewZoneParser(strings.NewReader(text), zone, "")
	rr, ok := parser.Next()
	if err := parser.Err(); err != nil {
		return nil, fmt.Errorf("parsing %q: %w", text, err)
	}
	if !ok {
		return nil, fmt.Errorf("parsing %q: no record", text)
	}
	return rr, nil
}
