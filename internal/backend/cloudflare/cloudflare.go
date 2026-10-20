// Package cloudflare is a backend that applies the updates through the API of
// Cloudflare, with an API token.
//
// Cloudflare stores records one by one, each with an identifier. tsigoat
// reads the records of a name, computes which records to create, delete or
// retime, and sends them in a single batch request, which Cloudflare applies
// in one transaction: an update applies whole, or not at all. Cloudflare
// manages the SOA and the NS records of the apex, which tsigoat shows but
// never changes, and serves its own addresses for the records that it
// proxies, which tsigoat leaves alone.
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/hosted"
	"github.com/enix/tsigoat/internal/backend/httpclient"
)

const (
	// DefaultURL is the base URL of the API.
	DefaultURL = "https://api.cloudflare.com/client/v4"
	// DefaultTimeout bounds every call to the API when Options set none.
	DefaultTimeout = 5 * time.Second
	// provider names Cloudflare in messages.
	provider = "Cloudflare"
	// pageSize is the number of records of a page of a listing.
	pageSize = 1000
)

// Options configure the backend.
type Options struct {
	// URL is the base URL of the API; DefaultURL when empty.
	URL string
	// APIToken authenticates the requests.
	APIToken string
	// ZoneIDs holds the identifiers of zones, by canonical name: tsigoat
	// finds the others by name.
	ZoneIDs map[string]string
	// Timeout bounds every call to the API; DefaultTimeout when zero.
	Timeout time.Duration
	// UserAgent identifies tsigoat.
	UserAgent string
}

// Backend is a Cloudflare backend. It is safe for concurrent use.
type Backend struct {
	api    *hosted.API
	limits *hosted.Limits

	// zones holds what tsigoat knows of the zones, by canonical name.
	zonesMu sync.Mutex
	zones   map[string]*zoneInfo
}

var (
	_ backend.Backend  = (*Backend)(nil)
	_ backend.TTLFloor = (*Backend)(nil)
)

// zoneInfo is what tsigoat knows of a zone.
type zoneInfo struct {
	id string
	// nameServers are the canonical names of the name servers that
	// Cloudflare assigned to the zone, when known.
	nameServers []string
	// complete tells whether nameServers was read.
	complete bool
}

// New returns a Cloudflare backend.
func New(options *Options) (*Backend, error) {
	base := strings.TrimRight(options.URL, "/")
	if base == "" {
		base = DefaultURL
	}
	if u, err := url.Parse(base); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("invalid Cloudflare API URL %q", options.URL)
	}
	if options.APIToken == "" {
		return nil, errors.New("missing Cloudflare API token")
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	client, err := httpclient.New(&httpclient.Options{})
	if err != nil {
		return nil, fmt.Errorf("configuring the client of the Cloudflare API: %w", err)
	}
	zones := map[string]*zoneInfo{}
	for name, id := range options.ZoneIDs {
		zones[dns.CanonicalName(name)] = &zoneInfo{id: id}
	}
	token := options.APIToken
	return &Backend{
		api: &hosted.API{
			Provider:  provider,
			Base:      base,
			Client:    client,
			Timeout:   timeout,
			UserAgent: options.UserAgent,
			Authorize: func(req *http.Request, _ []byte) error {
				req.Header.Set("Authorization", "Bearer "+token)
				return nil
			},
			Describe: describe,
		},
		limits: newLimits(),
		zones:  zones,
	}, nil
}

// MinTTL implements backend.TTLFloor.
func (*Backend) MinTTL() uint32 {
	return minTTL
}

// response is the envelope of the responses of the API.
type response[T any] struct {
	Success  bool       `json:"success"`
	Errors   []apiError `json:"errors"`
	Result   T          `json:"result"`
	PageInfo *struct {
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// get calls the API with a GET request, and decodes the result of the
// response into out.
func get[T any](ctx context.Context, b *Backend, path string, out *response[T]) error {
	if err := b.api.Do(ctx, http.MethodGet, path, nil, out); err != nil {
		return err
	}
	if !out.Success {
		return fmt.Errorf("%s API: GET %s failed: %s", provider, path, describeErrors(out.Errors))
	}
	return nil
}

// describe extracts the messages and the code of an error response, with
// the ray that identifies the request at Cloudflare.
func describe(header http.Header, body []byte) (message, code string) {
	var r response[json.RawMessage]
	if json.Unmarshal(body, &r) != nil || len(r.Errors) == 0 {
		return "", ""
	}
	message = describeErrors(r.Errors)
	if ray := header.Get("Cf-Ray"); ray != "" {
		message += " (ray " + ray + ")"
	}
	return message, strconv.Itoa(r.Errors[0].Code)
}

func describeErrors(errs []apiError) string {
	messages := make([]string, 0, len(errs))
	for _, e := range errs {
		messages = append(messages, e.Message+" ["+strconv.Itoa(e.Code)+"]")
	}
	return strings.Join(messages, "; ")
}

// zoneResult is a zone of the API.
type zoneResult struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	NameServers []string `json:"name_servers"`
}

// zone returns what tsigoat knows of a zone: its identifier, which it finds by
// name unless configured, and its name servers.
func (b *Backend) zone(ctx context.Context, name string) (*zoneInfo, error) {
	b.zonesMu.Lock()
	info, configured := b.zones[name]
	b.zonesMu.Unlock()
	if configured && info.complete {
		return info, nil
	}
	if configured {
		info = b.readZone(ctx, info.id)
	} else {
		var err error
		if info, err = b.findZone(ctx, name); err != nil {
			return nil, err
		}
	}
	b.zonesMu.Lock()
	b.zones[name] = info
	b.zonesMu.Unlock()
	return info, nil
}

// readZone reads the name servers of a zone. A token that may not read the
// zone itself still may read and write its records: the name servers stay
// unknown then.
func (b *Backend) readZone(ctx context.Context, id string) *zoneInfo {
	info := &zoneInfo{id: id, complete: true}
	var r response[zoneResult]
	if err := get(ctx, b, "/zones/"+url.PathEscape(id), &r); err == nil {
		info.nameServers = canonicalNames(r.Result.NameServers)
	}
	return info
}

// findZone finds a zone by name.
func (b *Backend) findZone(ctx context.Context, name string) (*zoneInfo, error) {
	var r response[[]zoneResult]
	query := url.Values{"name": {strings.TrimSuffix(name, ".")}}
	if err := get(ctx, b, "/zones?"+query.Encode(), &r); err != nil {
		return nil, fmt.Errorf("finding zone %s: %w (set its identifier in zoneIds, or let the token read the zone)", name, err)
	}
	i := indexOf(r.Result, func(z zoneResult) bool { return dns.CanonicalName(z.Name) == name })
	if i < 0 {
		return nil, fmt.Errorf("%s: %w: the API token sees no such zone", name, backend.ErrZoneNotFound)
	}
	return &zoneInfo{id: r.Result[i].ID, nameServers: canonicalNames(r.Result[i].NameServers), complete: true}, nil
}

func canonicalNames(names []string) []string {
	canonical := make([]string, 0, len(names))
	for _, name := range names {
		canonical = append(canonical, dns.CanonicalName(name))
	}
	return canonical
}

func indexOf[T any](list []T, match func(T) bool) int {
	for i, item := range list {
		if match(item) {
			return i
		}
	}
	return -1
}

// records returns the records of a name, with their identifiers.
func (b *Backend) records(ctx context.Context, zone *zoneInfo, zoneName, name string) ([]hosted.Record, error) {
	var records []hosted.Record
	for page := 1; ; page++ {
		query := url.Values{
			"name.exact": {strings.TrimSuffix(name, ".")},
			"page":       {strconv.Itoa(page)},
			"per_page":   {strconv.Itoa(pageSize)},
		}
		var r response[[]APIRecord]
		if err := get(ctx, b, "/zones/"+url.PathEscape(zone.id)+"/dns_records?"+query.Encode(), &r); err != nil {
			if hosted.StatusOf(err) == http.StatusNotFound {
				return nil, fmt.Errorf("%s: %w: %w", zoneName, backend.ErrZoneNotFound, err)
			}
			return nil, err
		}
		for i := range r.Result {
			record := &r.Result[i]
			// The filter ignores the case.
			if dns.CanonicalName(record.Name) != name {
				continue
			}
			held, err := FromAPI(record)
			if err != nil {
				return nil, fmt.Errorf("reading record %s of zone %s: %w", record.ID, zoneName, err)
			}
			if held.RR != nil {
				records = append(records, held)
			}
		}
		if r.PageInfo == nil || page >= r.PageInfo.TotalPages {
			return records, nil
		}
	}
}

// Lookup implements backend.Backend. At the apex, it adds the SOA that
// tsigoat makes up, and the NS records of the name servers of the zone.
func (b *Backend) Lookup(ctx context.Context, zone, name string) ([]backend.RRset, error) {
	zone, name = dns.CanonicalName(zone), dns.CanonicalName(name)
	info, err := b.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	records, err := b.records(ctx, info, zone, name)
	if err != nil {
		return nil, err
	}
	sets := hosted.RRsets(records)
	if name == zone {
		sets = append(sets, apex(zone, info, sets)...)
	}
	return sets, nil
}

// The SOA that tsigoat shows for the zones: Cloudflare serves its own, with
// these timers by default, and a serial that its API does not tell.
const (
	soaTTL     = 3600
	soaRefresh = 10000
	soaRetry   = 2400
	soaExpire  = 604800
	soaMinimum = 3600
	nsTTL      = 86400
)

// apex returns the RRsets that Cloudflare manages at the apex: the SOA, and
// the NS records of the name servers of the zone when the listing has none.
func apex(zone string, info *zoneInfo, sets []backend.RRset) []backend.RRset {
	primary := "ns.cloudflare.com."
	if len(info.nameServers) > 0 {
		primary = info.nameServers[0]
	}
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: soaTTL},
		Ns:  primary, Mbox: "dns.cloudflare.com.", Serial: 1,
		Refresh: soaRefresh, Retry: soaRetry, Expire: soaExpire, Minttl: soaMinimum,
	}
	added := []backend.RRset{{Name: zone, Type: dns.TypeSOA, TTL: soaTTL, Records: []dns.RR{soa}}}
	hasNS := indexOf(sets, func(set backend.RRset) bool { return set.Type == dns.TypeNS }) >= 0
	if !hasNS && len(info.nameServers) > 0 {
		ns := backend.RRset{Name: zone, Type: dns.TypeNS, TTL: nsTTL}
		for _, server := range info.nameServers {
			ns.Records = append(ns.Records, &dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: nsTTL}, Ns: server})
		}
		added = append(added, ns)
	}
	return added
}
