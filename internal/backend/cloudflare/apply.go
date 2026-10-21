package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/hosted"
)

// maxBatch bounds the operations of a batch, which the Free plan of
// Cloudflare limits to 200: tsigoat turns down a larger update rather than
// split it, which would lose its atomicity.
const maxBatch = 200

// Error codes of the API that tell that a record exists already: the zone
// changed since tsigoat read it.
const (
	codeRecordExists    = "81057"
	codeIdenticalRecord = "81058"
)

// batch is the body of a batch request: Cloudflare runs the deletions, then
// the patches, then the creations, in one transaction.
type batch struct {
	Deletes []idOnly    `json:"deletes,omitempty"`
	Patches []patch     `json:"patches,omitempty"`
	Posts   []APIRecord `json:"posts,omitempty"`
}

type idOnly struct {
	ID string `json:"id"`
}

// patch changes the TTL of a record, and keeps the rest of it, such as its
// comment and tags.
type patch struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
}

func (b *batch) size() int {
	return len(b.Deletes) + len(b.Patches) + len(b.Posts)
}

// Apply implements backend.Backend with a single batch request. When the
// batch finds the zone changed since tsigoat read it, tsigoat reads it again
// and sends another batch, once. When the outcome of the batch is unknown,
// after a timeout or a server error, tsigoat reads the records again, and
// reports a success if they are as the changes want them.
func (b *Backend) Apply(ctx context.Context, zone string, changes []backend.Change) error {
	zone = dns.CanonicalName(zone)
	if err := b.limits.Check(zone, changes); err != nil {
		return err
	}
	info, err := b.zone(ctx, zone)
	if err != nil {
		return err
	}
	for attempt := 1; ; attempt++ {
		body, err := b.plan(ctx, info, zone, changes)
		if err != nil || body.size() == 0 {
			return err
		}
		err = b.send(ctx, info, body)
		switch code := hosted.CodeOf(err); {
		case err == nil:
			return nil
		case (code == codeRecordExists || code == codeIdenticalRecord) && attempt == 1:
			continue
		case hosted.Ambiguous(err):
			return b.verify(ctx, info, zone, changes, err)
		default:
			return err
		}
	}
}

// plan reads the records of the names of the changes, and returns the batch
// that applies the changes.
func (b *Backend) plan(ctx context.Context, info *zoneInfo, zone string, changes []backend.Change) (*batch, error) {
	current, err := b.current(ctx, info, zone, changes)
	if err != nil {
		return nil, err
	}
	body := &batch{}
	for i := range changes {
		change := &changes[i]
		name := dns.CanonicalName(change.RRset.Name)
		ofType := hosted.OfType(current[name], change.RRset.Type)
		if reason := hosted.Locked(ofType); reason != "" {
			return nil, &backend.RejectionError{Rcode: dns.RcodeRefused, Reason: reason}
		}
		if reason := addressBesideProxied(change, current[name]); reason != "" {
			return nil, &backend.RejectionError{Rcode: dns.RcodeRefused, Reason: reason}
		}
		steps := hosted.Diff(ofType, change)
		for _, r := range steps.Delete {
			body.Deletes = append(body.Deletes, idOnly{ID: r.ID})
		}
		for _, r := range steps.Retime {
			body.Patches = append(body.Patches, patch{
				ID: r.ID, Name: apiName(name), Type: dns.TypeToString[change.RRset.Type], TTL: r.RR.Header().Ttl,
			})
		}
		for _, rr := range steps.Create {
			record, err := ToAPI(rr)
			if err != nil {
				return nil, err
			}
			body.Posts = append(body.Posts, record)
		}
	}
	if body.size() > maxBatch {
		return nil, &backend.RejectionError{
			Rcode:  dns.RcodeRefused,
			Reason: fmt.Sprintf("the update takes %d operations, more than the %d of a batch of Cloudflare", body.size(), maxBatch),
		}
	}
	return body, nil
}

// current reads the records of the names of the changes, by name.
func (b *Backend) current(ctx context.Context, info *zoneInfo, zone string, changes []backend.Change) (map[string][]hosted.Record, error) {
	current := map[string][]hosted.Record{}
	for i := range changes {
		name := dns.CanonicalName(changes[i].RRset.Name)
		if _, read := current[name]; read {
			continue
		}
		records, err := b.records(ctx, info, zone, name)
		if err != nil {
			return nil, err
		}
		current[name] = records
	}
	return current, nil
}

// addressBesideProxied returns why a change may not add addresses or a CNAME
// at a name whose addresses Cloudflare proxies, "" when it may: Cloudflare
// would proxy the new records too.
func addressBesideProxied(change *backend.Change, records []hosted.Record) string {
	if (change.Op != backend.Replace && change.Op != backend.Add) || !proxiable(change.RRset.Type) {
		return ""
	}
	for _, r := range records {
		if r.Locked != "" && proxiable(r.RR.Header().Rrtype) {
			return r.Locked
		}
	}
	return ""
}

func proxiable(rrtype uint16) bool {
	return rrtype == dns.TypeA || rrtype == dns.TypeAAAA || rrtype == dns.TypeCNAME
}

// apiName returns a canonical name as the API takes it.
func apiName(name string) string {
	return relative(name)
}

// send sends a batch.
func (b *Backend) send(ctx context.Context, info *zoneInfo, body *batch) error {
	var r response[any]
	path := "/zones/" + url.PathEscape(info.id) + "/dns_records/batch"
	if err := b.api.Do(ctx, http.MethodPost, path, body, &r); err != nil {
		return err
	}
	if !r.Success {
		return fmt.Errorf("%s API: POST %s failed: %s", provider, path, describeErrors(r.Errors))
	}
	return nil
}

// verify reads the records of the changes again after a request whose
// outcome is unknown: it returns nil if they show the changes. Otherwise the
// outcome stays unknown: the request may not have applied, or may apply
// still, after the response that tsigoat did not get.
func (b *Backend) verify(ctx context.Context, info *zoneInfo, zone string, changes []backend.Change, cause error) error {
	ctx, cancel := backend.RecoveryContext(ctx)
	defer cancel()
	current, err := b.current(ctx, info, zone, changes)
	if err != nil {
		return backend.Indeterminate(errors.Join(cause, fmt.Errorf("reading the records again: %w", err)))
	}
	if !hosted.Settled(current, changes) {
		return backend.Indeterminate(fmt.Errorf("%w; the records do not show the update, which may apply still", cause))
	}
	return nil
}
