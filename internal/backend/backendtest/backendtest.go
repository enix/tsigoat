// Package backendtest checks that a backend keeps the contract of
// backend.Backend: Lookup returns what Apply wrote, Apply replaces and
// deletes whole RRsets and leaves the others alone, and what the backend
// cannot hold is turned down with a *backend.RejectionError, without any
// change, never written approximately.
//
// The suite writes below a name of a zone, which it owns: it deletes the
// RRsets of the names that it uses before and after its cases. It runs on the
// in-memory backend and PowerDNS, on the simulated APIs of the hosted
// providers, and on the providers themselves, with the test zones and the
// credentials of a developer.
package backendtest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
)

// Suite describes a backend under test.
type Suite struct {
	// Backend is the backend under test.
	Backend backend.Backend
	// Zone is the canonical name of a zone of the backend.
	Zone string
	// Base is the canonical name, in Zone, below which the suite writes; no
	// other writer may use it.
	Base string
	// Rejected lists the cases that the backend must turn down, by name,
	// such as "types/HINFO", with the reason.
	Rejected map[string]string
	// Failing returns a change of the RRset owned by name that the backend
	// fails, so that the suite checks that a valid change beside it does not
	// apply either; no such check when nil.
	Failing func(name string) backend.Change
}

// Run runs the cases of the suite, each in a subtest.
func (s *Suite) Run(t *testing.T) {
	t.Helper()
	s.clean(t)
	t.Cleanup(func() { s.clean(t) })

	t.Run("lookup/missing", s.lookupMissing)
	t.Run("lookup/apex", s.lookupApex)
	t.Run("replace/one", s.replaceOne)
	t.Run("replace/several", s.replaceSeveral)
	t.Run("replace/swap", s.replaceSwap)
	t.Run("replace/ttl", s.replaceTTL)
	t.Run("replace/beside", s.replaceBeside)
	t.Run("delete/rrset", s.deleteRRset)
	t.Run("delete/missing", s.deleteMissing)
	t.Run("add/beside", s.addBeside)
	t.Run("add/new", s.addNew)
	t.Run("apply/several", s.applySeveral)
	t.Run("apply/atomic", s.applyAtomic)
	t.Run("ttl/zero", s.ttlZero)
	for _, c := range txtCases() {
		t.Run("txt/"+c.label, func(t *testing.T) { s.roundTrip(t, "txt/"+c.label, c.label+".txt", c.records) })
	}
	for _, c := range typeCases() {
		t.Run("types/"+c.label, func(t *testing.T) { s.roundTrip(t, "types/"+c.label, c.name, c.records) })
	}
	t.Run("apex/soa", s.apexSOA)
	t.Run("apex/ns", s.apexNS)
}

// name returns the canonical name of a relative name below Base.
func (s *Suite) name(relative string) string {
	return dns.CanonicalName(relative + "." + s.Base)
}

// usedNames returns every name that the cases write, below Base.
func usedNames() []string {
	txt, types := txtCases(), typeCases()
	names := make([]string, 0, 15+len(txt)+len(types))
	names = append(names,
		"one", "several", "swap", "ttl", "beside", "rrset", "missing-rrset",
		"add", "add-new", "first", "second", "third", "atomic", "failing", "zero",
	)
	for _, c := range txt {
		names = append(names, c.label+".txt")
	}
	for _, c := range types {
		names = append(names, c.name)
	}
	return names
}

// clean deletes the RRsets of every name that the cases use.
func (s *Suite) clean(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	if ctx.Err() != nil {
		// The cleanup of the whole suite runs once its context is over.
		ctx = context.WithoutCancel(ctx)
	}
	var changes []backend.Change
	for _, relative := range usedNames() {
		sets, err := s.Backend.Lookup(ctx, s.Zone, s.name(relative))
		if err != nil {
			t.Fatalf("cleaning up: Lookup(%s): %v", s.name(relative), err)
		}
		for _, set := range sets {
			changes = append(changes, backend.Change{Op: backend.Delete, RRset: backend.RRset{Name: set.Name, Type: set.Type}})
		}
	}
	if len(changes) == 0 {
		return
	}
	if err := s.Backend.Apply(ctx, s.Zone, changes); err != nil {
		t.Fatalf("cleaning up: Apply(%v): %v", changes, err)
	}
}

func (s *Suite) lookupMissing(t *testing.T) {
	s.expect(t, s.name("missing-rrset"))
}

func (s *Suite) lookupApex(t *testing.T) {
	sets, err := s.Backend.Lookup(t.Context(), s.Zone, s.Zone)
	if err != nil {
		t.Fatalf("Lookup(%s): %v", s.Zone, err)
	}
	i := slices.IndexFunc(sets, func(set backend.RRset) bool { return set.Type == dns.TypeSOA })
	if i < 0 || len(sets[i].Records) != 1 {
		t.Fatalf("Lookup(%s) = %v, want one SOA record", s.Zone, sets)
	}
	if _, ok := sets[i].Records[0].(*dns.SOA); !ok {
		t.Errorf("the SOA RRset holds %s", sets[i].Records[0])
	}
}

func (s *Suite) replaceOne(t *testing.T) {
	name := s.name("one")
	s.replace(t, parse(t, name, ttl, `TXT "one"`)...)
}

// replaceSeveral writes two values at once, as the challenges of a
// certificate for a name and its wildcard.
func (s *Suite) replaceSeveral(t *testing.T) {
	name := s.name("several")
	s.replace(t, parse(t, name, ttl, `TXT "first"`, `TXT "second"`)...)
}

func (s *Suite) replaceSwap(t *testing.T) {
	name := s.name("swap")
	s.replace(t, parse(t, name, ttl, `TXT "a"`, `TXT "b"`)...)
	s.replace(t, parse(t, name, ttl, `TXT "b"`, `TXT "c"`)...)
}

// replaceTTL changes the TTL of an RRset alone, which must reach every
// record.
func (s *Suite) replaceTTL(t *testing.T) {
	name := s.name("ttl")
	s.replace(t, parse(t, name, ttl, `TXT "a"`, `TXT "b"`)...)
	s.replace(t, parse(t, name, 2*ttl, `TXT "a"`, `TXT "b"`)...)
}

// replaceBeside replaces, then deletes, an RRset beside another one of the
// same name, which must not change.
func (s *Suite) replaceBeside(t *testing.T) {
	name := s.name("beside")
	address := parse(t, name, ttl, "A 192.0.2.1")
	s.replace(t, append(address, parse(t, name, ttl, `TXT "a"`)...)...)
	s.apply(t, replace(parse(t, name, ttl, `TXT "b"`)...)...)
	s.expect(t, name, append(slices.Clone(address), parse(t, name, ttl, `TXT "b"`)...)...)
	s.apply(t, backend.Change{Op: backend.Delete, RRset: backend.RRset{Name: name, Type: dns.TypeTXT}})
	s.expect(t, name, address...)
}

func (s *Suite) deleteRRset(t *testing.T) {
	name := s.name("rrset")
	s.replace(t, parse(t, name, ttl, `TXT "a"`, `TXT "b"`)...)
	s.apply(t, backend.Change{Op: backend.Delete, RRset: backend.RRset{Name: name, Type: dns.TypeTXT}})
	s.expect(t, name)
}

// deleteMissing deletes an RRset that does not exist, which changes nothing:
// the zone may have changed since the engine read it.
func (s *Suite) deleteMissing(t *testing.T) {
	name := s.name("missing-rrset")
	s.apply(t, backend.Change{Op: backend.Delete, RRset: backend.RRset{Name: name, Type: dns.TypeTXT}})
	s.expect(t, name)
}

// addBeside adds records to an RRset and removes others, which leaves the
// rest of the RRset alone: the changes of concurrent updates survive.
func (s *Suite) addBeside(t *testing.T) {
	name := s.name("add")
	s.replace(t, parse(t, name, ttl, `TXT "a"`)...)
	s.apply(t, add(parse(t, name, ttl, `TXT "b"`)...)...)
	s.expect(t, name, parse(t, name, ttl, `TXT "a"`, `TXT "b"`)...)
	// A record held already, and a record missing, change nothing.
	s.apply(t, add(parse(t, name, ttl, `TXT "a"`)...)...)
	s.apply(t, remove(parse(t, name, ttl, `TXT "missing"`)...)...)
	s.expect(t, name, parse(t, name, ttl, `TXT "a"`, `TXT "b"`)...)
	s.apply(t, remove(parse(t, name, ttl, `TXT "a"`)...)...)
	s.expect(t, name, parse(t, name, ttl, `TXT "b"`)...)
	// An RRset that exists keeps its TTL.
	s.apply(t, add(parse(t, name, 2*ttl, `TXT "c"`)...)...)
	s.expect(t, name, parse(t, name, ttl, `TXT "b"`, `TXT "c"`)...)
}

// addNew adds records to an RRset that does not exist, which takes the TTL
// of the change, then removes them, which deletes it.
func (s *Suite) addNew(t *testing.T) {
	name := s.name("add-new")
	sets := parse(t, name, 2*ttl, `TXT "first"`, `TXT "second"`)
	s.apply(t, add(sets...)...)
	s.expect(t, name, sets...)
	s.apply(t, remove(s.lookup(t, name)...)...)
	s.expect(t, name)
}

// applySeveral applies changes of several names at once.
func (s *Suite) applySeveral(t *testing.T) {
	first, second, third := s.name("first"), s.name("second"), s.name("third")
	s.replace(t, parse(t, third, ttl, `TXT "gone"`)...)
	changes := replace(parse(t, first, ttl, `TXT "first"`)...)
	changes = append(changes, replace(parse(t, second, ttl, "A 192.0.2.2")...)...)
	changes = append(changes, backend.Change{Op: backend.Delete, RRset: backend.RRset{Name: third, Type: dns.TypeTXT}})
	s.apply(t, changes...)
	s.expect(t, first, parse(t, first, ttl, `TXT "first"`)...)
	s.expect(t, second, parse(t, second, ttl, "A 192.0.2.2")...)
	s.expect(t, third)
}

// applyAtomic checks that a valid change does not apply beside one that the
// backend fails, made on a name that holds a TXT record.
func (s *Suite) applyAtomic(t *testing.T) {
	if s.Failing == nil {
		t.Skip("no failing change for this backend")
	}
	valid, failing := s.name("atomic"), s.name("failing")
	occupied := parse(t, failing, ttl, `TXT "occupied"`)
	s.replace(t, occupied...)
	changes := append(replace(parse(t, valid, ttl, `TXT "valid"`)...), s.Failing(failing))
	if err := s.Backend.Apply(t.Context(), s.Zone, changes); err == nil {
		t.Fatalf("Apply(%v) succeeded, want an error", changes)
	}
	s.expect(t, valid)
	s.expect(t, failing, occupied...)
}

// ttlZero writes a TTL of zero, which a backend writes, or turns down when
// its provider has a minimum TTL: "0" means another TTL at some providers.
func (s *Suite) ttlZero(t *testing.T) {
	name := s.name("zero")
	sets := parse(t, name, 0, `TXT "zero"`)
	if s.rejects(t, "ttl/zero", replace(sets...)) {
		s.expect(t, name)
		return
	}
	s.expect(t, name, sets...)
}

// apexSOA checks that a backend that leaves the SOA to its provider turns
// down its changes. The suite does not change the apex of other backends.
func (s *Suite) apexSOA(t *testing.T) {
	if _, ok := s.Rejected["apex/soa"]; !ok {
		t.Skip("the backend writes the SOA: the suite leaves the apex alone")
	}
	sets := s.lookup(t, s.Zone)
	i := slices.IndexFunc(sets, func(set backend.RRset) bool { return set.Type == dns.TypeSOA })
	if i < 0 {
		t.Fatalf("no SOA at %s", s.Zone)
	}
	soa, ok := dns.Copy(sets[i].Records[0]).(*dns.SOA)
	if !ok {
		t.Fatalf("the SOA RRset holds %s", sets[i].Records[0])
	}
	soa.Serial++
	if !s.rejects(t, "apex/soa", replace(backend.RRset{Name: s.Zone, Type: dns.TypeSOA, TTL: sets[i].TTL, Records: []dns.RR{soa}})) {
		t.Fatal("the SOA changed")
	}
	s.expect(t, s.Zone, sets...)
}

// apexNS checks that a backend that leaves the NS records of the apex to its
// provider turns down their changes.
func (s *Suite) apexNS(t *testing.T) {
	if _, ok := s.Rejected["apex/ns"]; !ok {
		t.Skip("the backend writes the NS records of the apex: the suite leaves the apex alone")
	}
	sets := s.lookup(t, s.Zone)
	ns := parse(t, s.Zone, ttl, "NS ns.example.net.")
	if i := slices.IndexFunc(sets, func(set backend.RRset) bool { return set.Type == dns.TypeNS }); i >= 0 {
		ns[0].TTL = sets[i].TTL
		ns[0].Records = append(ns[0].Records, sets[i].Records...)
	}
	if !s.rejects(t, "apex/ns", replace(ns...)) {
		t.Fatal("the NS records of the apex changed")
	}
	s.expect(t, s.Zone, sets...)
}

// replace returns the changes that replace the RRsets.
func replace(sets ...backend.RRset) []backend.Change {
	changes := make([]backend.Change, 0, len(sets))
	for _, set := range sets {
		changes = append(changes, backend.Change{Op: backend.Replace, RRset: set})
	}
	return changes
}

// add returns the changes that add the records of the RRsets.
func add(sets ...backend.RRset) []backend.Change {
	changes := make([]backend.Change, 0, len(sets))
	for _, set := range sets {
		changes = append(changes, backend.Change{Op: backend.Add, RRset: set})
	}
	return changes
}

// remove returns the changes that remove the records of the RRsets.
func remove(sets ...backend.RRset) []backend.Change {
	changes := make([]backend.Change, 0, len(sets))
	for _, set := range sets {
		changes = append(changes, backend.Change{Op: backend.Remove, RRset: set})
	}
	return changes
}

// replace writes RRsets of one name, which must then hold them alone.
func (s *Suite) replace(t *testing.T, sets ...backend.RRset) {
	t.Helper()
	s.apply(t, replace(sets...)...)
	s.expect(t, sets[0].Name, sets...)
}

// apply applies changes, which must succeed.
func (s *Suite) apply(t *testing.T, changes ...backend.Change) {
	t.Helper()
	if err := s.Backend.Apply(t.Context(), s.Zone, changes); err != nil {
		t.Fatalf("Apply(%v): %v", changes, err)
	}
}

// lookup returns the RRsets of a name.
func (s *Suite) lookup(t *testing.T, name string) []backend.RRset {
	t.Helper()
	sets, err := s.Backend.Lookup(t.Context(), s.Zone, name)
	if err != nil {
		t.Fatalf("Lookup(%s): %v", name, err)
	}
	return sets
}

// expect checks that name holds the RRsets, and nothing else.
func (s *Suite) expect(t *testing.T, name string, want ...backend.RRset) {
	t.Helper()
	got := s.lookup(t, name)
	if diff := compare(got, want); diff != "" {
		t.Errorf("Lookup(%s) differs, %s\ngot:\n%s\nwant:\n%s", name, diff, describe(got), describe(want))
	}
}

// compare returns how got differs from want, "" when it does not.
func compare(got, want []backend.RRset) string {
	if len(got) != len(want) {
		return fmt.Sprintf("%d RRsets instead of %d", len(got), len(want))
	}
	for _, w := range want {
		i := slices.IndexFunc(got, func(g backend.RRset) bool { return g.Type == w.Type })
		if i < 0 {
			return "missing " + dns.Type(w.Type).String()
		}
		g := got[i]
		if g.Name != w.Name {
			return fmt.Sprintf("name %s instead of %s", g.Name, w.Name)
		}
		if g.TTL != w.TTL {
			return fmt.Sprintf("TTL %d instead of %d for %s", g.TTL, w.TTL, dns.Type(w.Type))
		}
		if !sameRecords(g.Records, w.Records) {
			return "other records for " + dns.Type(w.Type).String()
		}
	}
	return ""
}

// sameRecords reports whether two lists hold the same records, whatever their
// order, their TTL and the forms of their presentation format.
func sameRecords(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = canonical(a), canonical(b)
	used := make([]bool, len(b))
	for _, x := range a {
		i := slices.IndexFunc(b, func(y dns.RR) bool { return dns.IsDuplicate(x, y) })
		for i >= 0 && used[i] {
			next := slices.IndexFunc(b[i+1:], func(y dns.RR) bool { return dns.IsDuplicate(x, y) })
			if next < 0 {
				i = -1
				break
			}
			i += next + 1
		}
		if i < 0 {
			return false
		}
		used[i] = true
	}
	return true
}

// canonical returns the canonical forms of records, or the records
// themselves when they do not encode.
func canonical(records []dns.RR) []dns.RR {
	forms := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		if form, err := backend.Canonical(rr); err == nil {
			rr = form
		}
		forms = append(forms, rr)
	}
	return forms
}

// describe lists RRsets, one record per line, sorted.
func describe(sets []backend.RRset) string {
	var lines []string
	for _, set := range sets {
		for _, rr := range set.Records {
			lines = append(lines, fmt.Sprintf("  %s %d %s %s", set.Name, set.TTL, dns.Type(set.Type), backend.RData(rr)))
		}
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}
