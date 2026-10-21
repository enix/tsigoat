package ovh

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/hosted"
)

const (
	// refreshAttempts bounds the attempts to refresh a zone: a refresh
	// publishes the zone as it stands, so that it may go again.
	refreshAttempts = 3
	// defaultRefreshDelay is the default of Options.RefreshDelay: OVHcloud
	// runs one refresh of a zone at a time.
	defaultRefreshDelay = time.Second
)

// step is a request that changes a record, which writes what it did in a
// journal once its answer tells it.
type step struct {
	describe string
	do       func(ctx context.Context, j *journal) error
}

// journal holds what the requests of an update did, as their answers tell:
// the records that they created, with the identifiers that OVHcloud gave
// them, and the records that they deleted or retimed, as they were. A
// recovery takes back what the journal holds alone: a record of the same
// data at OVHcloud may come from another writer, such as another instance of
// tsigoat.
type journal struct {
	created, deleted, retimed []hosted.Record
}

// empty reports whether the journal holds nothing to take back.
func (j *journal) empty() bool {
	return len(j.created) == 0 && len(j.deleted) == 0 && len(j.retimed) == 0
}

// names returns the canonical names of the records of the journal, once each.
func (j *journal) names() []string {
	var names []string
	for _, r := range slices.Concat(j.created, j.deleted, j.retimed) {
		if name := dns.CanonicalName(r.RR.Header().Name); !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}

// plan holds the requests that change the records of an update, by kind:
// deletions first, so that a CNAME may replace other data at a name, or the
// reverse, then retimes, then creations.
type plan struct {
	deletions, retimes, creations []step
}

// add adds the requests that carry out steps on current, the records of their
// RRset.
func (p *plan) add(b *Backend, zone string, steps *hosted.Steps, current []hosted.Record) {
	for _, r := range steps.Delete {
		p.deletions = append(p.deletions, b.deletion(zone, r))
	}
	for _, r := range steps.Retime {
		was := r
		if i := slices.IndexFunc(current, func(c hosted.Record) bool { return c.ID == r.ID }); i >= 0 {
			was = current[i]
		}
		p.retimes = append(p.retimes, b.retime(zone, r, was))
	}
	for _, rr := range steps.Create {
		p.creations = append(p.creations, b.creation(zone, rr))
	}
}

// steps returns the requests, in order.
func (p *plan) steps() []step {
	return slices.Concat(p.deletions, p.retimes, p.creations)
}

// Apply implements backend.Backend: it deletes the records that go, retimes
// those that stay, creates the new ones, then refreshes the zone.
//
// OVHcloud has no transaction: when a request or the refresh fails, Apply
// takes back what the journal of the update holds, and publishes the zone. A
// request that failed without telling whether it applied, as after a timeout,
// may have applied, or apply still: nothing tells its effect apart from what
// another writer does, so that the outcome is unknown.
func (b *Backend) Apply(ctx context.Context, zone string, changes []backend.Change) error {
	zone = dns.CanonicalName(zone)
	if err := b.limits.Check(zone, changes); err != nil {
		return err
	}
	names := make([]string, 0, len(changes))
	for i := range changes {
		if name := dns.CanonicalName(changes[i].RRset.Name); !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	before, err := b.read(ctx, zone, names)
	if err != nil {
		return err
	}
	var p plan
	for i := range changes {
		change := &changes[i]
		current := hosted.OfType(before[dns.CanonicalName(change.RRset.Name)], change.RRset.Type)
		diff := hosted.Diff(current, change)
		p.add(b, zone, &diff, current)
	}
	steps := p.steps()
	if len(steps) == 0 {
		return nil
	}
	var j journal
	for _, s := range steps {
		if err := s.do(ctx, &j); err != nil {
			return b.recover(ctx, zone, &j, fmt.Errorf("%s: %w", s.describe, err), hosted.Ambiguous(err), false)
		}
	}
	if err := b.refresh(ctx, zone); err != nil {
		return b.recover(ctx, zone, &j, fmt.Errorf("refreshing the zone, which publishes it: %w", err), false, true)
	}
	return nil
}

// read reads the records of names, by name.
func (b *Backend) read(ctx context.Context, zone string, names []string) (map[string][]hosted.Record, error) {
	records := make(map[string][]hosted.Record, len(names))
	for _, name := range names {
		held, err := b.records(ctx, zone, name)
		if err != nil {
			return nil, err
		}
		records[name] = held
	}
	return records, nil
}

// deletion returns the step that deletes a record. A record that is gone
// already is no error, and stays out of the journal: another writer deleted
// it.
func (b *Backend) deletion(zone string, r hosted.Record) step {
	path := zonePath(zone) + "/record/" + r.ID
	return step{
		describe: "deleting " + r.RR.String(),
		do: func(ctx context.Context, j *journal) error {
			err := b.do(ctx, http.MethodDelete, path, nil, nil)
			switch {
			case hosted.StatusOf(err) == http.StatusNotFound:
				return nil
			case err != nil:
				return err
			}
			j.deleted = append(j.deleted, r)
			return nil
		},
	}
}

// retime returns the step that gives a record the TTL that its RR carries; was
// is the record as it stands.
func (b *Backend) retime(zone string, r, was hosted.Record) step {
	path := zonePath(zone) + "/record/" + r.ID
	ttl := r.RR.Header().Ttl
	return step{
		describe: "changing the TTL of " + r.RR.String(),
		do: func(ctx context.Context, j *journal) error {
			if err := b.do(ctx, http.MethodPut, path, map[string]uint32{"ttl": ttl}, nil); err != nil {
				return err
			}
			j.retimed = append(j.retimed, was)
			return nil
		},
	}
}

// creation returns the step that creates a record, as a TXT record when it
// was one of the SPF, DKIM or DMARC types of OVHcloud.
func (b *Backend) creation(zone string, rr dns.RR) step {
	body := toAPI(rr, zone)
	return step{
		describe: "creating " + rr.String(),
		do: func(ctx context.Context, j *journal) error {
			var created struct {
				ID int64 `json:"id"`
			}
			if err := b.do(ctx, http.MethodPost, zonePath(zone)+"/record", body, &created); err != nil {
				return err
			}
			j.created = append(j.created, hosted.Record{ID: strconv.FormatInt(created.ID, 10), RR: rr})
			return nil
		},
	}
}

// recover takes back what the journal holds, after cause made the update
// fail, within the recovery budget, then publishes the zone when needed.
// pending tells that the request that failed may have applied, or apply
// still; published tells that a refresh failed, which may have published the
// update anyway. It returns the error of the update, which tells whether its
// outcome is unknown.
func (b *Backend) recover(ctx context.Context, zone string, j *journal, cause error, pending, published bool) error {
	ctx, cancel := backend.RecoveryContext(ctx)
	defer cancel()
	tookBack, err := b.takeBack(ctx, zone, j)
	if err != nil {
		return backend.Indeterminate(fmt.Errorf("%w; taking back what the update did failed, so that the zone may hold "+
			"part of the update, which its next refresh publishes: %w", cause, err))
	}
	if !published && !tookBack {
		if pending {
			return backend.Indeterminate(fmt.Errorf("%w; the request may have applied, or apply still, "+
				"and the next refresh of the zone publish it", cause))
		}
		// Nothing changed.
		return cause
	}
	// Publish the zone without the update: a refresh, the one that failed or
	// another, may have published some of it.
	if err := b.refresh(ctx, zone); err != nil {
		if published || pending {
			return backend.Indeterminate(fmt.Errorf("%w; what the update did is taken back, but publishing the zone failed, "+
				"so that the name servers may serve the update: %w", cause, err))
		}
		return fmt.Errorf("%w; what the update did is taken back, but refreshing the zone failed: %w", cause, err)
	}
	if pending {
		return backend.Indeterminate(fmt.Errorf("%w; what the update did is taken back, but the failed request "+
			"may have applied, or apply still, and the next refresh of the zone publish it", cause))
	}
	return fmt.Errorf("%w; what the update did is taken back", cause)
}

// takeBack takes back what the journal holds: it deletes the records that the
// update created, creates again those that it deleted, unless a record of the
// same data stands, and gives back their TTL to those that it retimed; then
// it reads the records again to check them. It reports whether it had to
// change something.
func (b *Backend) takeBack(ctx context.Context, zone string, j *journal) (bool, error) {
	if j.empty() {
		return false, nil
	}
	names := j.names()
	now, err := b.read(ctx, zone, names)
	if err != nil {
		return false, err
	}
	steps := b.reverse(zone, j, now).steps()
	if len(steps) == 0 {
		return false, nil
	}
	var undone journal
	for _, s := range steps {
		if stepErr := s.do(ctx, &undone); stepErr != nil {
			return true, fmt.Errorf("%s: %w", s.describe, stepErr)
		}
	}
	after, err := b.read(ctx, zone, names)
	if err != nil {
		return true, fmt.Errorf("reading the records again: %w", err)
	}
	return true, j.held(after)
}

// reverse returns the requests that take back what the journal holds, from
// now, the records as they stand.
func (b *Backend) reverse(zone string, j *journal, now map[string][]hosted.Record) *plan {
	var p plan
	for _, r := range j.created {
		if find(now, r) != nil {
			p.deletions = append(p.deletions, b.deletion(zone, r))
		}
	}
	for _, r := range j.retimed {
		if current := find(now, r); current != nil && current.RR.Header().Ttl != r.RR.Header().Ttl {
			p.retimes = append(p.retimes, b.retime(zone, r, *current))
		}
	}
	for _, r := range j.deleted {
		if !holdsData(now, r) {
			p.creations = append(p.creations, b.creation(zone, r.RR))
		}
	}
	return &p
}

// held returns why records still hold part of what the journal holds, nil when
// they hold none of it.
func (j *journal) held(records map[string][]hosted.Record) error {
	for _, r := range j.created {
		if find(records, r) != nil {
			return fmt.Errorf("the record %s that the update created stays", r.RR)
		}
	}
	for _, r := range j.retimed {
		if current := find(records, r); current != nil && current.RR.Header().Ttl != r.RR.Header().Ttl {
			return fmt.Errorf("the record %s keeps the TTL that the update gave it", current.RR)
		}
	}
	for _, r := range j.deleted {
		if !holdsData(records, r) {
			return fmt.Errorf("the record %s that the update deleted is still missing", r.RR)
		}
	}
	return nil
}

// find returns the record of records, by name, with the identifier of r; nil
// when it is gone.
func find(records map[string][]hosted.Record, r hosted.Record) *hosted.Record {
	held := records[dns.CanonicalName(r.RR.Header().Name)]
	if i := slices.IndexFunc(held, func(h hosted.Record) bool { return h.ID == r.ID }); i >= 0 {
		return &held[i]
	}
	return nil
}

// holdsData reports whether records, by name, hold a record of the data of r.
func holdsData(records map[string][]hosted.Record, r hosted.Record) bool {
	return slices.ContainsFunc(records[dns.CanonicalName(r.RR.Header().Name)], func(h hosted.Record) bool {
		return dns.IsDuplicate(h.RR, r.RR)
	})
}

// refresh publishes the zone, as it stands, to the name servers.
func (b *Backend) refresh(ctx context.Context, zone string) error {
	delay := b.refreshDelay
	for attempt := 1; ; attempt++ {
		err := b.do(ctx, http.MethodPost, zonePath(zone)+"/refresh", nil, nil)
		if err == nil || attempt == refreshAttempts {
			return err
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < delay {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(delay):
		}
		delay *= 2
	}
}
