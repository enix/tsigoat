package ovh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
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

// step is a request that changes a record.
type step struct {
	describe string
	do       func(ctx context.Context) error
}

// plan holds the requests that change the records of an update, by kind:
// deletions first, so that a CNAME may replace other data at a name, or the
// reverse, then retimes, then creations.
type plan struct {
	deletions, retimes, creations []step
}

// add adds the requests that carry out steps.
func (p *plan) add(b *Backend, zone string, steps *hosted.Steps) {
	for _, r := range steps.Delete {
		p.deletions = append(p.deletions, b.deletion(zone, r))
	}
	for _, r := range steps.Retime {
		p.retimes = append(p.retimes, b.retime(zone, r))
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
// A request that fails may have applied anyway, at OVHcloud, before its
// response was lost: when a step or the refresh fails, Apply reads the
// records again, brings them back to their content before the update,
// whatever the requests did, and publishes the zone. When that fails too,
// the outcome is unknown.
func (b *Backend) Apply(ctx context.Context, zone string, changes []backend.Change) error {
	zone = dns.CanonicalName(zone)
	if err := b.limits.Check(zone, changes); err != nil {
		return err
	}
	before, err := b.read(ctx, zone, changes)
	if err != nil {
		return err
	}
	var p plan
	for i := range changes {
		change := &changes[i]
		diff := hosted.Diff(hosted.OfType(before[dns.CanonicalName(change.RRset.Name)], change.RRset.Type), change)
		p.add(b, zone, &diff)
	}
	steps := p.steps()
	if len(steps) == 0 {
		return nil
	}
	for _, s := range steps {
		if err := s.do(ctx); err != nil {
			return b.recover(ctx, zone, before, changes, fmt.Errorf("%s: %w", s.describe, err), false)
		}
	}
	if err := b.refresh(ctx, zone); err != nil {
		return b.recover(ctx, zone, before, changes, fmt.Errorf("refreshing the zone, which publishes it: %w", err), true)
	}
	return nil
}

// read reads the records of the names of the changes, by name.
func (b *Backend) read(ctx context.Context, zone string, changes []backend.Change) (map[string][]hosted.Record, error) {
	records := map[string][]hosted.Record{}
	for i := range changes {
		name := dns.CanonicalName(changes[i].RRset.Name)
		if _, read := records[name]; read {
			continue
		}
		held, err := b.records(ctx, zone, name)
		if err != nil {
			return nil, err
		}
		records[name] = held
	}
	return records, nil
}

// deletion returns the step that deletes a record. A record that is gone
// already is no error.
func (b *Backend) deletion(zone string, r hosted.Record) step {
	path := zonePath(zone) + "/record/" + r.ID
	return step{
		describe: "deleting " + r.RR.String(),
		do: func(ctx context.Context) error {
			err := b.do(ctx, http.MethodDelete, path, nil, nil)
			if hosted.StatusOf(err) == http.StatusNotFound {
				return nil
			}
			return err
		},
	}
}

// retime returns the step that gives a record the TTL that its RR carries.
func (b *Backend) retime(zone string, r hosted.Record) step {
	path := zonePath(zone) + "/record/" + r.ID
	ttl := r.RR.Header().Ttl
	return step{
		describe: "changing the TTL of " + r.RR.String(),
		do: func(ctx context.Context) error {
			return b.do(ctx, http.MethodPut, path, map[string]uint32{"ttl": ttl}, nil)
		},
	}
}

// creation returns the step that creates a record, as a TXT record when it
// was one of the SPF, DKIM or DMARC types of OVHcloud.
func (b *Backend) creation(zone string, rr dns.RR) step {
	body := toAPI(rr, zone)
	return step{
		describe: "creating " + rr.String(),
		do: func(ctx context.Context) error {
			return b.do(ctx, http.MethodPost, zonePath(zone)+"/record", body, nil)
		},
	}
}

// recover brings the RRsets of the changes back to their content before the
// update, after cause made it fail, within the recovery budget, then
// publishes the zone when needed; published tells that a refresh failed,
// which may have published the update anyway. It returns the error of the
// update, which tells whether its outcome is unknown.
func (b *Backend) recover(ctx context.Context, zone string, before map[string][]hosted.Record, changes []backend.Change, cause error, published bool) error {
	ctx, cancel := backend.RecoveryContext(ctx)
	defer cancel()
	restored, err := b.restore(ctx, zone, before, changes)
	if err != nil {
		return backend.Indeterminate(fmt.Errorf("%w; restoring the records as they were failed, so that the zone may hold "+
			"part of the update, which its next refresh publishes: %w", cause, err))
	}
	if !published && !restored {
		// Nothing changed.
		return cause
	}
	// Publish the records as they were: a refresh, the one that failed or
	// another, may have published some of the update.
	if err := b.refresh(ctx, zone); err != nil {
		if published {
			return backend.Indeterminate(fmt.Errorf("%w; the records are as they were, but publishing them failed, "+
				"so that the name servers may serve the update: %w", cause, err))
		}
		return fmt.Errorf("%w; the records are as they were, but refreshing the zone failed: %w", cause, err)
	}
	return fmt.Errorf("%w; the records are as they were", cause)
}

// restore reads the records of the changes again, takes back what each change
// did, and checks it: an RRset replaced or deleted comes back as it was
// before the update, the records added go, and the records removed come
// back, so that the records that concurrent updates wrote meanwhile stay. It
// reports whether it had to change something.
func (b *Backend) restore(ctx context.Context, zone string, before map[string][]hosted.Record, changes []backend.Change) (bool, error) {
	now, err := b.read(ctx, zone, changes)
	if err != nil {
		return false, err
	}
	var p plan
	for i := range changes {
		steps := undo(before, now, &changes[i])
		p.add(b, zone, &steps)
	}
	steps := p.steps()
	if len(steps) == 0 {
		return false, nil
	}
	for _, s := range steps {
		if stepErr := s.do(ctx); stepErr != nil {
			return true, fmt.Errorf("%s: %w", s.describe, stepErr)
		}
	}
	after, err := b.read(ctx, zone, changes)
	if err != nil {
		return true, fmt.Errorf("reading the records restored: %w", err)
	}
	for i := range changes {
		if check := undo(before, after, &changes[i]); !check.Empty() {
			return true, errors.New("the records read back still hold part of the update")
		}
	}
	return true, nil
}

// undo returns the steps that take back a change, from the records of its
// name before the update and as they stand.
func undo(before, now map[string][]hosted.Record, change *backend.Change) hosted.Steps {
	name, rrtype := dns.CanonicalName(change.RRset.Name), change.RRset.Type
	return hosted.Undo(hosted.OfType(before[name], rrtype), hosted.OfType(now[name], rrtype), change)
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
