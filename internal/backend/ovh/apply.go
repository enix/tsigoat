package ovh

import (
	"context"
	"errors"
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
	// refreshDelay is the delay before the second attempt of a refresh,
	// which doubles for the next one: OVHcloud runs one refresh of a zone
	// at a time.
	refreshDelay = time.Second
)

// step is a request that changes a record, and the request that undoes it.
type step struct {
	describe string
	do, undo func(ctx context.Context) error
}

// Apply implements backend.Backend: it deletes the records that go, retimes
// those that stay, creates the new ones, then refreshes the zone. Deletions
// come first, so that a CNAME may replace other data at a name, or the
// reverse. When a step or the refresh fails, Apply undoes the steps done.
func (b *Backend) Apply(ctx context.Context, zone string, changes []backend.Change) error {
	zone = dns.CanonicalName(zone)
	if err := b.limits.Check(zone, changes); err != nil {
		return err
	}
	steps, err := b.plan(ctx, zone, changes)
	if err != nil {
		return err
	}
	if len(steps) == 0 && !b.isUnpublished(zone) {
		return nil
	}
	for i, s := range steps {
		if err := s.do(ctx); err != nil {
			return b.undo(ctx, zone, steps[:i], fmt.Errorf("%s: %w", s.describe, err))
		}
	}
	if err := b.refresh(ctx, zone); err != nil {
		return b.undo(ctx, zone, steps, fmt.Errorf("refreshing the zone, which publishes it: %w", err))
	}
	b.setUnpublished(zone, false)
	return nil
}

// plan reads the records of the names of the changes, and returns the steps
// that apply the changes, deletions first, then retimes, then creations.
func (b *Backend) plan(ctx context.Context, zone string, changes []backend.Change) ([]step, error) {
	current := map[string][]hosted.Record{}
	var deletions, retimes, creations []step
	for i := range changes {
		change := &changes[i]
		name := dns.CanonicalName(change.RRset.Name)
		records, read := current[name]
		if !read {
			var err error
			if records, err = b.records(ctx, zone, name); err != nil {
				return nil, err
			}
			current[name] = records
		}
		ofType := slices.DeleteFunc(slices.Clone(records), func(r hosted.Record) bool {
			return r.RR.Header().Rrtype != change.RRset.Type
		})
		diff := hosted.Diff(ofType, change)
		for _, r := range diff.Delete {
			deletions = append(deletions, b.deletion(zone, r))
		}
		for _, r := range diff.Retime {
			former := ofType[slices.IndexFunc(ofType, func(c hosted.Record) bool { return c.ID == r.ID })]
			retimes = append(retimes, b.retime(zone, r, former.RR.Header().Ttl))
		}
		for _, rr := range diff.Create {
			creations = append(creations, b.creation(zone, rr))
		}
	}
	return slices.Concat(deletions, retimes, creations), nil
}

// deletion returns the step that deletes a record, which creating it again
// undoes, as a TXT record when it was one of the SPF, DKIM or DMARC types of
// OVHcloud.
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
		undo: func(ctx context.Context) error {
			return b.do(ctx, http.MethodPost, zonePath(zone)+"/record", toAPI(r.RR, zone), nil)
		},
	}
}

// retime returns the step that gives a record the TTL of its RRset, which
// giving it its former TTL undoes.
func (b *Backend) retime(zone string, r hosted.Record, former uint32) step {
	path := zonePath(zone) + "/record/" + r.ID
	ttl := r.RR.Header().Ttl
	return step{
		describe: "changing the TTL of " + r.RR.String(),
		do: func(ctx context.Context) error {
			return b.do(ctx, http.MethodPut, path, map[string]uint32{"ttl": ttl}, nil)
		},
		undo: func(ctx context.Context) error {
			return b.do(ctx, http.MethodPut, path, map[string]uint32{"ttl": former}, nil)
		},
	}
}

// creation returns the step that creates a record, which deleting it undoes.
func (b *Backend) creation(zone string, rr dns.RR) step {
	body := toAPI(rr, zone)
	var id int64
	return step{
		describe: "creating " + rr.String(),
		do: func(ctx context.Context) error {
			var created apiRecord
			if err := b.do(ctx, http.MethodPost, zonePath(zone)+"/record", body, &created); err != nil {
				return err
			}
			id = created.ID
			return nil
		},
		undo: func(ctx context.Context) error {
			if id == 0 {
				// The API has answered without the identifier: find it.
				found, err := b.find(ctx, zone, rr)
				if err != nil {
					return err
				}
				id = found
			}
			return b.do(ctx, http.MethodDelete, zonePath(zone)+"/record/"+strconv.FormatInt(id, 10), nil, nil)
		},
	}
}

// find returns the identifier of a record.
func (b *Backend) find(ctx context.Context, zone string, rr dns.RR) (int64, error) {
	records, err := b.records(ctx, zone, dns.CanonicalName(rr.Header().Name))
	if err != nil {
		return 0, err
	}
	for _, r := range records {
		if dns.IsDuplicate(r.RR, rr) {
			return strconv.ParseInt(r.ID, 10, 64) //nolint:wrapcheck // the identifiers are numbers
		}
	}
	return 0, fmt.Errorf("record %s not found", rr)
}

// undo undoes the steps done, in reverse order, and returns the error that
// made them fail, telling whether the zone holds part of the update still.
// The zone is then refreshed, in case another refresh published the steps
// done in between.
func (b *Backend) undo(ctx context.Context, zone string, done []step, cause error) error {
	// Undo even after the deadline of the update, within the timeout of the
	// calls, so that the zone does not keep half of it.
	ctx = context.WithoutCancel(ctx)
	var failures []error
	for _, s := range slices.Backward(done) {
		if err := s.undo(ctx); err != nil {
			failures = append(failures, fmt.Errorf("undoing %s: %w", s.describe, err))
		}
	}
	if len(failures) > 0 {
		b.setUnpublished(zone, true)
		return fmt.Errorf("%w; undoing the steps before it failed, and the zone holds part of the update, "+
			"which its next refresh publishes: %w", cause, errors.Join(failures...))
	}
	if len(done) > 0 {
		if err := b.refresh(ctx, zone); err != nil {
			b.setUnpublished(zone, true)
		}
	}
	return fmt.Errorf("%w; the steps before it were undone", cause)
}

// refresh publishes the zone, as it stands, to the name servers.
func (b *Backend) refresh(ctx context.Context, zone string) error {
	delay := refreshDelay
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

func (b *Backend) isUnpublished(zone string) bool {
	b.unpublishedMu.Lock()
	defer b.unpublishedMu.Unlock()
	return b.unpublished[zone]
}

func (b *Backend) setUnpublished(zone string, unpublished bool) {
	b.unpublishedMu.Lock()
	defer b.unpublishedMu.Unlock()
	if unpublished {
		b.unpublished[zone] = true
	} else {
		delete(b.unpublished, zone)
	}
}
