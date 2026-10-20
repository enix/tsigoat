package scaleway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/hosted"
)

// patch is the body of a PATCH request, whose changes Scaleway applies in
// order, as one version of the zone.
type patch struct {
	Changes []recordChange `json:"changes"`
	// ReturnAllRecords false keeps the response small.
	ReturnAllRecords bool `json:"return_all_records"`
	// DisallowNewZoneCreation true keeps Scaleway from creating a zone for
	// the names of the changes, which would hide every name below it.
	DisallowNewZoneCreation bool `json:"disallow_new_zone_creation"`
}

type recordChange struct {
	Add    *addChange    `json:"add,omitempty"`
	Set    *setChange    `json:"set,omitempty"`
	Delete *deleteChange `json:"delete,omitempty"`
}

type addChange struct {
	Records []APIRecord `json:"records"`
}

type setChange struct {
	ID      string      `json:"id"`
	Records []APIRecord `json:"records"`
}

type deleteChange struct {
	ID string `json:"id"`
}

// Apply implements backend.Backend with a single PATCH request: the
// deletions of the records that go, the retimes of those that stay, then the
// creations. When the outcome of the request is unknown, after a timeout or a
// server error, tsigoat reads the records again, and reports a success if
// they are as the changes want them.
func (b *Backend) Apply(ctx context.Context, zone string, changes []backend.Change) error {
	zone = dns.CanonicalName(zone)
	if err := b.limits.Check(zone, changes); err != nil {
		return err
	}
	current, err := b.current(ctx, zone, changes)
	if err != nil {
		return err
	}
	var deletions, retimes []recordChange
	var additions []APIRecord
	for i := range changes {
		change := &changes[i]
		ofType := hosted.OfType(current[dns.CanonicalName(change.RRset.Name)], change.RRset.Type)
		if reason := hosted.Locked(ofType); reason != "" {
			return &backend.RejectionError{Rcode: dns.RcodeRefused, Reason: reason}
		}
		steps := hosted.Diff(ofType, change)
		for _, r := range steps.Delete {
			deletions = append(deletions, recordChange{Delete: &deleteChange{ID: r.ID}})
		}
		for _, r := range steps.Retime {
			retimes = append(retimes, recordChange{Set: &setChange{ID: r.ID, Records: []APIRecord{ToAPI(r.RR, zone)}}})
		}
		for _, rr := range steps.Create {
			additions = append(additions, ToAPI(rr, zone))
		}
	}
	body := patch{Changes: slices.Concat(deletions, retimes), DisallowNewZoneCreation: true}
	if len(additions) > 0 {
		body.Changes = append(body.Changes, recordChange{Add: &addChange{Records: additions}})
	}
	if len(body.Changes) == 0 {
		return nil
	}
	err = b.api.Do(ctx, http.MethodPatch, recordsPath(zone), &body, nil)
	if err != nil && hosted.Ambiguous(err) {
		return b.verify(ctx, zone, changes, err)
	}
	return notFound(zone, err)
}

// current reads the records of the names of the changes, by name.
func (b *Backend) current(ctx context.Context, zone string, changes []backend.Change) (map[string][]hosted.Record, error) {
	current := map[string][]hosted.Record{}
	for i := range changes {
		name := dns.CanonicalName(changes[i].RRset.Name)
		if _, read := current[name]; read {
			continue
		}
		records, err := b.records(ctx, zone, name)
		if err != nil {
			return nil, err
		}
		current[name] = records
	}
	return current, nil
}

// verify reads the records of the changes again after a request whose
// outcome is unknown: it returns nil if they are as the changes want them,
// cause otherwise.
func (b *Backend) verify(ctx context.Context, zone string, changes []backend.Change, cause error) error {
	current, err := b.current(context.WithoutCancel(ctx), zone, changes)
	if err != nil {
		return errors.Join(cause, fmt.Errorf("reading the records again: %w", err))
	}
	if !hosted.Settled(current, changes) {
		return fmt.Errorf("%w; the records do not show the update", cause)
	}
	return nil
}
