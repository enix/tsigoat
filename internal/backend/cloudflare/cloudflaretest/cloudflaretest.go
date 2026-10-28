// Package cloudflaretest simulates the parts of the API of Cloudflare that the
// cloudflare backend calls, with the behaviors that matter to it: records with
// identifiers, a batch endpoint that applies whole or not at all, the checks
// and error codes of Cloudflare, and the content that it renders for the
// types with fields, such as SRV records whose content leaves out the
// priority, or hexadecimal strings in upper case.
package cloudflaretest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/cloudflare"
	"github.com/enix/tsigoat/internal/backend/hosted/hostedtest"
)

// Token is the API token that the simulated API accepts.
const Token = "test-token" // gitleaks:allow (fixture)

// The bounds of the TTLs that Cloudflare accepts, but 1 for automatic.
const (
	minTTL = 60
	maxTTL = 86400
)

// API is a simulated API of Cloudflare.
type API struct {
	URL   string
	store *hostedtest.Store[cloudflare.APIRecord]

	mu sync.Mutex
	// zones holds the zones, by identifier.
	zones map[string]zone
	// failures holds the responses of the next requests to the batch
	// endpoint, which go before the batch applies.
	failures []failure
	requests int
	// held holds the batch requests that HoldBatch keeps for Land.
	held []heldBatch
	// waiting counts the held requests that wait for their client to give
	// up.
	waiting int
}

// heldBatch is a batch request that applies after its client gave up on it.
type heldBatch struct {
	zoneID, zoneName string
	data             []byte
}

type zone struct {
	name        string
	nameServers []string
}

type failure struct {
	status  int
	code    int
	message string
	// late holds the request until its client gives up on it, then keeps it
	// for Land; holding is closed once it holds the request, read whole.
	late    bool
	holding chan struct{}
}

// New starts a simulated API until the end of the test.
func New(t *testing.T) *API {
	t.Helper()
	a := &API{store: hostedtest.NewStore[cloudflare.APIRecord](), zones: map[string]zone{}}
	server := httptest.NewServer(a)
	t.Cleanup(server.Close)
	a.URL = server.URL
	return a
}

// CreateZone creates or empties a zone, assigns it name servers, and returns
// its identifier.
func (a *API) CreateZone(name string, nameServers ...string) string {
	name = strings.TrimSuffix(dns.CanonicalName(name), ".")
	a.mu.Lock()
	defer a.mu.Unlock()
	id := fmt.Sprintf("%032x", len(a.zones)+1)
	for existing, z := range a.zones {
		if z.name == name {
			id = existing
		}
	}
	servers := make([]string, 0, len(nameServers))
	for _, ns := range nameServers {
		servers = append(servers, strings.TrimSuffix(ns, "."))
	}
	a.zones[id] = zone{name: name, nameServers: servers}
	a.store.SetZone(id)
	return id
}

// Records returns the records of a zone.
func (a *API) Records(zoneID string) []cloudflare.APIRecord {
	entries, _ := a.store.Records(zoneID, nil)
	records := make([]cloudflare.APIRecord, 0, len(entries))
	for _, e := range entries {
		r := e.Record
		r.ID = e.ID
		records = append(records, r)
	}
	return records
}

// SetProxied proxies the A, AAAA and CNAME records of a name, or stops.
func (a *API) SetProxied(zoneID, name string, proxied bool) {
	_ = a.store.Update(zoneID, func(tx *hostedtest.Tx[cloudflare.APIRecord]) error {
		for _, e := range tx.Records(func(r cloudflare.APIRecord) bool { return r.Name == strings.TrimSuffix(name, ".") }) {
			if r := e.Record; r.Type == "A" || r.Type == typeAAAA || r.Type == typeCNAME {
				r.Proxied = proxied
				_ = tx.Put(e.ID, r)
			}
		}
		return nil
	})
}

// FailBatch makes the next batch request fail with an error response, before
// it applies; a status of 0 drops the connection after the batch applies.
func (a *API) FailBatch(status, code int, message string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failures = append(a.failures, failure{status: status, code: code, message: message})
}

// HoldBatch makes the next batch request wait until its client gives up on
// it, then keeps it, not applied, until Land applies it: a request that still
// applies after its timeout, or the cancellation of its update. The channel
// that it returns is closed once the request waits, read whole.
func (a *API) HoldBatch() <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	holding := make(chan struct{})
	a.failures = append(a.failures, failure{late: true, holding: holding})
	return holding
}

// Land applies the batch requests that HoldBatch kept, as Cloudflare would
// once their client gave up.
func (a *API) Land() error {
	// The server learns that the client gave up after the client does.
	for deadline := time.Now().Add(5 * time.Second); a.waitingRequests() > 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	a.mu.Lock()
	held := a.held
	a.held = nil
	a.mu.Unlock()
	for _, h := range held {
		var body batchBody
		if err := json.Unmarshal(h.data, &body); err != nil {
			return fmt.Errorf("decoding a held batch: %w", err)
		}
		if err := a.store.Update(h.zoneID, func(tx *hostedtest.Tx[cloudflare.APIRecord]) error {
			return apply(tx, h.zoneName, &body)
		}); err != nil {
			return fmt.Errorf("applying a held batch: %w", err)
		}
	}
	return nil
}

// Requests returns the number of requests served.
func (a *API) Requests() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.requests
}

// apiError is an error of the API.
type apiError struct {
	status  int
	code    int
	message string
}

func (e *apiError) Error() string {
	return e.message
}

func fail(status, code int, format string, args ...any) error {
	return &apiError{status: status, code: code, message: fmt.Sprintf(format, args...)}
}

// ServeHTTP serves the API.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.requests++
	a.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer "+Token {
		reply(w, nil, nil, fail(http.StatusForbidden, 10000, "Authentication error"))
		return
	}
	if handler := a.route(r); handler != nil {
		handler(w, r)
		return
	}
	reply(w, nil, nil, fail(http.StatusNotFound, 7003, "Could not route to %s, perhaps your object identifier is invalid?", r.URL.Path))
}

// route returns the handler of a request, nil for the routes that the
// simulated API does not serve.
func (a *API) route(r *http.Request) http.HandlerFunc {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if parts[0] != zonesPath {
		return nil
	}
	switch {
	case r.Method == http.MethodGet && len(parts) == 1:
		return a.listZones
	case r.Method == http.MethodGet && len(parts) == 2:
		return func(w http.ResponseWriter, _ *http.Request) { a.getZone(w, parts[1]) }
	case r.Method == http.MethodGet && len(parts) == 3 && parts[2] == recordsPath:
		return func(w http.ResponseWriter, r *http.Request) { a.listRecords(w, r, parts[1]) }
	case r.Method == http.MethodPost && len(parts) == 4 && parts[2] == recordsPath && parts[3] == "batch":
		return func(w http.ResponseWriter, r *http.Request) { a.batch(w, r, parts[1]) }
	default:
		return nil
	}
}

// Path segments and types that the simulated API names more than once.
const (
	zonesPath   = "zones"
	recordsPath = "dns_records"
	typeAAAA    = "AAAA"
	typeCNAME   = "CNAME"
)

// reply writes the envelope of a response.
func reply(w http.ResponseWriter, result, info any, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cf-Ray", "8f0123456789abcd-CDG")
	body := map[string]any{"success": err == nil, "errors": []any{}, "messages": []any{}, "result": result}
	if info != nil {
		body["result_info"] = info
	}
	if e, ok := errors.AsType[*apiError](err); ok {
		body["errors"] = []any{map[string]any{"code": e.code, "message": e.message}}
		w.WriteHeader(e.status)
	} else if err != nil {
		body["errors"] = []any{map[string]any{"code": 1000, "message": err.Error()}}
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = json.NewEncoder(w).Encode(body)
}

type zoneResult struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	NameServers []string `json:"name_servers"`
	Status      string   `json:"status"`
}

func (a *API) listZones(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.URL.Query().Get("name"))
	a.mu.Lock()
	defer a.mu.Unlock()
	results := []zoneResult{}
	for id, z := range a.zones {
		if name == "" || z.name == name {
			results = append(results, zoneResult{ID: id, Name: z.name, NameServers: z.nameServers, Status: "active"})
		}
	}
	reply(w, results, map[string]int{"page": 1, "per_page": 20, "count": len(results), "total_count": len(results), "total_pages": 1}, nil)
}

func (a *API) getZone(w http.ResponseWriter, id string) {
	a.mu.Lock()
	z, ok := a.zones[id]
	a.mu.Unlock()
	if !ok {
		reply(w, nil, nil, fail(http.StatusNotFound, 7003, "Could not route to /zones/%s, perhaps your object identifier is invalid?", id))
		return
	}
	reply(w, zoneResult{ID: id, Name: z.name, NameServers: z.nameServers, Status: "active"}, nil, nil)
}

func (a *API) listRecords(w http.ResponseWriter, r *http.Request, zoneID string) {
	query := r.URL.Query()
	name := strings.ToLower(query.Get("name.exact"))
	if name == "" {
		name = strings.ToLower(query.Get("name"))
	}
	page, _ := strconv.Atoi(cmpOr(query.Get("page"), "1"))
	perPage, _ := strconv.Atoi(cmpOr(query.Get("per_page"), "100"))
	entries, err := a.store.Records(zoneID, func(rec cloudflare.APIRecord) bool { return name == "" || rec.Name == name })
	if err != nil {
		reply(w, nil, nil, fail(http.StatusNotFound, 7003, "Could not route to /zones/%s/dns_records, perhaps your object identifier is invalid?", zoneID))
		return
	}
	total := len(entries)
	start, end := min((page-1)*perPage, total), min(page*perPage, total)
	results := make([]cloudflare.APIRecord, 0, end-start)
	for _, e := range entries[start:end] {
		rec := e.Record
		rec.ID = e.ID
		results = append(results, rec)
	}
	pages := max((total+perPage-1)/perPage, 1)
	reply(w, results, map[string]int{"page": page, "per_page": perPage, "count": len(results), "total_count": total, "total_pages": pages}, nil)
}

func cmpOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// batchBody is the body of a batch request.
type batchBody struct {
	Deletes []struct {
		ID string `json:"id"`
	} `json:"deletes"`
	Patches []struct {
		ID   string  `json:"id"`
		Name string  `json:"name"`
		Type string  `json:"type"`
		TTL  *uint32 `json:"ttl"`
	} `json:"patches"`
	Puts  []json.RawMessage      `json:"puts"`
	Posts []cloudflare.APIRecord `json:"posts"`
}

func (a *API) batch(w http.ResponseWriter, r *http.Request, zoneID string) {
	a.mu.Lock()
	var next *failure
	if len(a.failures) > 0 {
		next = &a.failures[0]
		a.failures = a.failures[1:]
	}
	zoneName := a.zones[zoneID].name
	a.mu.Unlock()
	if next != nil && next.status != 0 {
		reply(w, nil, nil, fail(next.status, next.code, "%s", next.message))
		return
	}

	data, _ := io.ReadAll(r.Body)
	if next != nil && next.late {
		a.mu.Lock()
		a.waiting++
		a.mu.Unlock()
		close(next.holding)
		<-r.Context().Done()
		a.mu.Lock()
		a.waiting--
		a.held = append(a.held, heldBatch{zoneID: zoneID, zoneName: zoneName, data: data})
		a.mu.Unlock()
		return
	}
	var body batchBody
	if err := json.Unmarshal(data, &body); err != nil {
		reply(w, nil, nil, fail(http.StatusBadRequest, 9207, "Request body is invalid."))
		return
	}
	if len(body.Puts) > 0 {
		reply(w, nil, nil, fail(http.StatusBadRequest, 1004, "the simulated API takes no puts"))
		return
	}
	err := a.store.Update(zoneID, func(tx *hostedtest.Tx[cloudflare.APIRecord]) error {
		return apply(tx, zoneName, &body)
	})
	if errors.Is(err, hostedtest.ErrNoZone) {
		err = fail(http.StatusNotFound, 7003, "Could not route to /zones/%s/dns_records/batch, perhaps your object identifier is invalid?", zoneID)
	}
	if err == nil && next != nil {
		// The batch applied, but the client never learns it.
		hijackAndClose(w)
		return
	}
	reply(w, map[string]any{"deletes": []any{}, "patches": []any{}, "puts": []any{}, "posts": []any{}}, nil, err)
}

// hijackAndClose closes the connection without a response.
func hijackAndClose(w http.ResponseWriter) {
	if hijacker, ok := w.(http.Hijacker); ok {
		if conn, _, err := hijacker.Hijack(); err == nil {
			_ = conn.Close()
		}
	}
}

// apply applies a batch in a transaction: deletions, patches, then posts.
func apply(tx *hostedtest.Tx[cloudflare.APIRecord], zoneName string, body *batchBody) error {
	for _, d := range body.Deletes {
		if err := tx.Delete(d.ID); err != nil {
			return fail(http.StatusBadRequest, 81044, "failed to DELETE record with id %s. The error was: Record does not exist.", d.ID)
		}
	}
	for _, p := range body.Patches {
		rec, err := tx.Get(p.ID)
		if err != nil {
			return fail(http.StatusBadRequest, 81044, "failed to PATCH record with id %s. The error was: Record does not exist.", p.ID)
		}
		if p.Type != "" && p.Type != rec.Type {
			return fail(http.StatusBadRequest, 9000, "failed to PATCH record with id %s. The error was: the type of a record cannot change.", p.ID)
		}
		if p.TTL != nil {
			if err := checkTTL(*p.TTL); err != nil {
				return err
			}
			rec.TTL = *p.TTL
		}
		_ = tx.Put(p.ID, rec)
	}
	for i := range body.Posts {
		rec, err := render(&body.Posts[i], zoneName)
		if err == nil {
			err = checkConflicts(tx, &rec)
		}
		if err != nil {
			return prefixed(err, "POST", &body.Posts[i])
		}
		tx.Create(rec)
	}
	return nil
}

// prefixed prefixes the message of an error as the batch endpoint does.
func prefixed(err error, method string, rec *cloudflare.APIRecord) error {
	if e, ok := errors.AsType[*apiError](err); ok {
		e.message = fmt.Sprintf("failed to %s record with name %s and type %s. The error was: %s", method, rec.Name, rec.Type, e.message)
		return e
	}
	return err
}

func checkTTL(ttl uint32) error {
	if ttl != 1 && (ttl < minTTL || ttl > maxTTL) {
		return fail(http.StatusBadRequest, 9021, "TTL must be between %d and %d seconds, or 1 for Automatic.", minTTL, maxTTL)
	}
	return nil
}

// checkConflicts checks a new record against the records of its name.
func checkConflicts(tx *hostedtest.Tx[cloudflare.APIRecord], rec *cloudflare.APIRecord) error {
	for _, e := range tx.Records(func(r cloudflare.APIRecord) bool { return r.Name == rec.Name }) {
		other := e.Record
		switch {
		case other.Type == rec.Type && strings.EqualFold(other.Content, rec.Content) && optionalEqual(other.Priority, rec.Priority):
			return fail(http.StatusBadRequest, 81058, "An identical record already exists.")
		case rec.Type == typeCNAME && slices.Contains([]string{"A", typeAAAA, typeCNAME}, other.Type):
			return fail(http.StatusBadRequest, 81053, "An A, AAAA, or CNAME record with that host already exists.")
		case other.Type == typeCNAME && (rec.Type == "A" || rec.Type == typeAAAA):
			return fail(http.StatusBadRequest, 81054, "A CNAME record with that host already exists.")
		}
	}
	return nil
}

func optionalEqual(a, b *uint16) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

// Rejected returns the cases of the conformance suite of the backends that
// the cloudflare backend turns down, with the reason, for the simulated API
// and for Cloudflare itself.
func Rejected() map[string]string {
	return map[string]string{
		"types/HINFO": "Cloudflare holds no HINFO record",
		"types/RP":    "Cloudflare holds no RP record",
		"types/DNAME": "Cloudflare holds no DNAME record",
		"txt/empty":   "Cloudflare does not serve empty TXT records",
		"txt/utf8":    "tsigoat keeps TXT strings to printable ASCII",
		"ttl/zero":    "Cloudflare holds no TTL below 60",
		"apex/soa":    "Cloudflare manages the SOA record",
		"apex/ns":     "Cloudflare manages the NS records of the apex",
	}
}

// Failing returns a change that Cloudflare fails, for the conformance suite:
// a CNAME record whose target is its own name.
func Failing(name string) backend.Change {
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: name}
	return backend.Change{Op: backend.Replace, RRset: backend.RRset{Name: name, Type: dns.TypeCNAME, TTL: 300, Records: []dns.RR{cname}}}
}

// Divergences returns the scenarios of test/scenario that fail on the
// simulated API on purpose, with the reason.
func Divergences() map[string]string {
	return map[string]string{
		"policy/soa-rule":  "Cloudflare manages the SOA record: tsigoat turns its changes down",
		"records/hinfo":    "Cloudflare holds no HINFO record",
		"records/ttl-zero": "Cloudflare holds no TTL below 60: tsigoat raises it",
		"records/txt-utf8": "tsigoat keeps TXT strings to printable ASCII",
	}
}

// waitingRequests returns the number of held requests that wait for their
// client to give up.
func (a *API) waitingRequests() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.waiting
}
