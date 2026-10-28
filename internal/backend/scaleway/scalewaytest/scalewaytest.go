// Package scalewaytest simulates the parts of the Domains and DNS API of
// Scaleway that the scaleway backend calls, with the behaviors that matter to
// it: records with identifiers, a PATCH request whose changes apply in order
// and as a whole, a loose name filter that does not filter the apex, pages of
// 20 records by default, the 403 of an unknown zone, the TXT data that it
// quotes, and the TTL of the NS records that it raises.
package scalewaytest

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
	"github.com/enix/tsigoat/internal/backend/hosted/hostedtest"
	"github.com/enix/tsigoat/internal/backend/scaleway"
)

// SecretKey is the secret key that the simulated API accepts.
const SecretKey = "11111111-2222-3333-4444-555555555555" // gitleaks:allow (fixture)

// typeCNAME is the type of the CNAME records.
const typeCNAME = "CNAME"

// The bounds of the TTLs that the API accepts, and the TTL of the NS records.
const (
	minTTL = 60
	maxTTL = 2592000
	nsTTL  = 1800
)

// API is a simulated Domains and DNS API of Scaleway.
type API struct {
	URL   string
	store *hostedtest.Store[scaleway.APIRecord]

	mu sync.Mutex
	// failures holds the responses of the next PATCH requests, which go
	// before the changes apply; a status of 0 drops the connection after
	// they apply.
	failures []failure
	requests int
	// held holds the PATCH requests that HoldPatch keeps for Land.
	held []heldPatch
	// waiting counts the held requests that wait for their client to give
	// up.
	waiting int
}

type failure struct {
	status  int
	message string
	// late holds the request until its client gives up on it, then keeps it
	// for Land; holding is closed once it holds the request, read whole.
	late    bool
	holding chan struct{}
}

// heldPatch is a PATCH request that applies after its client gave up on it.
type heldPatch struct {
	zone string
	body patchBody
}

// New starts a simulated API until the end of the test.
func New(t *testing.T) *API {
	t.Helper()
	a := &API{store: hostedtest.NewStore[scaleway.APIRecord]()}
	server := httptest.NewServer(a)
	t.Cleanup(server.Close)
	a.URL = server.URL
	return a
}

// CreateZone creates or empties a zone, with the NS records of its apex.
func (a *API) CreateZone(zone string) {
	zone = strings.TrimSuffix(dns.CanonicalName(zone), ".")
	a.store.SetZone(zone,
		scaleway.APIRecord{Name: "", Type: "NS", Data: "ns0.dom.scw.cloud.", TTL: nsTTL},
		scaleway.APIRecord{Name: "", Type: "NS", Data: "ns1.dom.scw.cloud.", TTL: nsTTL},
	)
}

// AddRaw adds a record as another client of the API would have stored it,
// such as a dynamic record.
func (a *API) AddRaw(zone string, r *scaleway.APIRecord) {
	added := *r
	_ = a.store.Update(strings.TrimSuffix(zone, "."), func(tx *hostedtest.Tx[scaleway.APIRecord]) error {
		tx.Create(added)
		return nil
	})
}

// Records returns the records of a zone.
func (a *API) Records(zone string) []scaleway.APIRecord {
	entries, _ := a.store.Records(strings.TrimSuffix(zone, "."), nil)
	records := make([]scaleway.APIRecord, 0, len(entries))
	for _, e := range entries {
		r := e.Record
		r.ID = e.ID
		records = append(records, r)
	}
	return records
}

// FailPatch makes the next PATCH request fail with the status and the
// message, before it applies; a status of 0 drops the connection after it
// applies.
func (a *API) FailPatch(status int, message string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failures = append(a.failures, failure{status: status, message: message})
}

// HoldPatch makes the next PATCH request wait until its client gives up on it,
// then keeps it, not applied, until Land applies it: a request that still
// applies after its timeout, or the cancellation of its update. The channel
// that it returns is closed once the request waits, read whole.
func (a *API) HoldPatch() <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	holding := make(chan struct{})
	a.failures = append(a.failures, failure{late: true, holding: holding})
	return holding
}

// Land applies the PATCH requests that HoldPatch kept, as Scaleway would once
// their client gave up.
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
		if err := a.applyPatch(h.zone, &h.body); err != nil {
			return fmt.Errorf("applying a held PATCH: %w", err)
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
	message string
}

func (e *apiError) Error() string {
	return e.message
}

func fail(status int, format string, args ...any) error {
	return &apiError{status: status, message: fmt.Sprintf(format, args...)}
}

func reply(w http.ResponseWriter, body any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if e, ok := errors.AsType[*apiError](err); ok {
		w.WriteHeader(e.status)
		body = map[string]string{"message": e.message}
	}
	_ = json.NewEncoder(w).Encode(body)
}

// ServeHTTP serves the API.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.requests++
	a.mu.Unlock()
	if r.Header.Get("X-Auth-Token") != SecretKey {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"authentication is denied","method":"api_key","reason":"not_found","type":"denied_authentication"}`))
		return
	}
	zone, ok := strings.CutPrefix(r.URL.Path, "/domain/v2beta1/dns-zones/")
	zone, ok2 := strings.CutSuffix(zone, "/records")
	if !ok || !ok2 || !a.store.HasZone(zone) {
		reply(w, nil, fail(http.StatusForbidden, "domain not found"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.list(w, r, zone)
	case http.MethodPatch:
		a.patch(w, r, zone)
	default:
		reply(w, nil, fail(http.StatusMethodNotAllowed, "method not allowed"))
	}
}

// list lists the records of a zone. The name filter matches the names that
// start with it, without regard to case; an empty filter matches every name.
func (a *API) list(w http.ResponseWriter, r *http.Request, zone string) {
	query := r.URL.Query()
	prefix := strings.ToLower(query.Get("name"))
	page, _ := strconv.Atoi(cmpOr(query.Get("page"), "1"))
	pageSize, _ := strconv.Atoi(cmpOr(query.Get("page_size"), "20"))
	entries, _ := a.store.Records(zone, func(rec scaleway.APIRecord) bool {
		return strings.HasPrefix(strings.ToLower(rec.Name), prefix)
	})
	total := len(entries)
	start, end := min((page-1)*pageSize, total), min(page*pageSize, total)
	records := make([]scaleway.APIRecord, 0, end-start)
	for _, e := range entries[start:end] {
		rec := e.Record
		rec.ID = e.ID
		records = append(records, rec)
	}
	reply(w, map[string]any{"records": records, "total_count": total}, nil)
}

func cmpOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// patchBody is the body of a PATCH request.
type patchBody struct {
	Changes []struct {
		Add *struct {
			Records []scaleway.APIRecord `json:"records"`
		} `json:"add"`
		Set *struct {
			ID      string               `json:"id"`
			Records []scaleway.APIRecord `json:"records"`
		} `json:"set"`
		Delete *struct {
			ID string `json:"id"`
		} `json:"delete"`
		Clear *struct{} `json:"clear"`
	} `json:"changes"`
	DisallowNewZoneCreation bool `json:"disallow_new_zone_creation"`
}

func (a *API) patch(w http.ResponseWriter, r *http.Request, zone string) {
	a.mu.Lock()
	var next *failure
	if len(a.failures) > 0 {
		next = &a.failures[0]
		a.failures = a.failures[1:]
	}
	a.mu.Unlock()
	if next != nil && next.status != 0 {
		reply(w, nil, fail(next.status, "%s", next.message))
		return
	}
	data, _ := io.ReadAll(r.Body)
	var body patchBody
	if err := json.Unmarshal(data, &body); err != nil || !body.DisallowNewZoneCreation {
		reply(w, nil, fail(http.StatusBadRequest, "invalid argument: the simulated API wants disallow_new_zone_creation"))
		return
	}
	if next != nil && next.late {
		a.mu.Lock()
		a.waiting++
		a.mu.Unlock()
		close(next.holding)
		<-r.Context().Done()
		a.mu.Lock()
		a.waiting--
		a.held = append(a.held, heldPatch{zone: zone, body: body})
		a.mu.Unlock()
		return
	}
	err := a.applyPatch(zone, &body)
	if err == nil && next != nil {
		if hijacker, ok := w.(http.Hijacker); ok {
			if conn, _, hijackErr := hijacker.Hijack(); hijackErr == nil {
				_ = conn.Close()
				return
			}
		}
	}
	reply(w, map[string]any{"records": []any{}}, err)
}

// applyPatch applies the changes of a PATCH request, all or none.
func (a *API) applyPatch(zone string, body *patchBody) error {
	return a.store.Update(zone, func(tx *hostedtest.Tx[scaleway.APIRecord]) error {
		for _, change := range body.Changes {
			if err := apply(tx, zone, change.Add, change.Set, change.Delete, change.Clear != nil); err != nil {
				return err
			}
		}
		return nil
	})
}

// apply applies one change of a PATCH request.
func apply(tx *hostedtest.Tx[scaleway.APIRecord], zone string, add *struct {
	Records []scaleway.APIRecord `json:"records"`
}, set *struct {
	ID      string               `json:"id"`
	Records []scaleway.APIRecord `json:"records"`
}, del *struct {
	ID string `json:"id"`
}, clearing bool,
) error {
	switch {
	case clearing:
		return fail(http.StatusBadRequest, "the simulated API takes no clear")
	case del != nil:
		if err := tx.Delete(del.ID); err != nil {
			return fail(http.StatusForbidden, "record not found")
		}
	case set != nil:
		if _, err := tx.Get(set.ID); err != nil || len(set.Records) != 1 {
			return fail(http.StatusForbidden, "record not found")
		}
		rec, err := normalize(tx, zone, &set.Records[0], set.ID)
		if err != nil {
			return err
		}
		return tx.Put(set.ID, rec)
	case add != nil:
		for i := range add.Records {
			rec, err := normalize(tx, zone, &add.Records[i], "")
			if err != nil {
				return err
			}
			tx.Create(rec)
		}
	}
	return nil
}

// recordTypes lists the types that the API accepts.
func recordTypes() []string {
	return []string{
		"A", "AAAA", "CNAME", "TXT", "SRV", "TLSA", "MX", "NS", "PTR", "CAA", "ALIAS", "LOC", "SSHFP", "HINFO", "RP",
		"URI", "DS", "NAPTR", "DNAME", "SVCB", "HTTPS",
	}
}

// normalize checks a record as the API does, and returns it as the API stores
// it; replacing is the identifier of the record that a set replaces.
func normalize(tx *hostedtest.Tx[scaleway.APIRecord], zone string, posted *scaleway.APIRecord, replacing string) (scaleway.APIRecord, error) {
	rec := *posted
	rec.ID = ""
	switch {
	case !slices.Contains(recordTypes(), rec.Type):
		return rec, fail(http.StatusBadRequest, "invalid argument: type %q", rec.Type)
	case rec.TTL == 0:
		return rec, fail(http.StatusBadRequest, "invalid argument: ttl is required")
	case rec.TTL < minTTL || rec.TTL > maxTTL:
		return rec, fail(http.StatusBadRequest, "invalid argument: ttl must be between %d and %d", minTTL, maxTTL)
	case rec.Type == typeCNAME && rec.Name == "":
		return rec, fail(http.StatusBadRequest, "invalid argument: cname can not be used in root zone, you can use alias")
	case strings.HasSuffix(rec.Name, "."):
		rec.Name = strings.TrimSuffix(strings.TrimSuffix(rec.Name, "."), "."+zone)
	}
	if rec.Type == "NS" {
		rec.TTL = max(rec.TTL, nsTTL)
	}
	if rec.Type == "TXT" && !strings.HasPrefix(rec.Data, `"`) {
		rec.Data = `"` + rec.Data + `"`
	}
	for _, e := range tx.Records(func(other scaleway.APIRecord) bool { return strings.EqualFold(other.Name, rec.Name) }) {
		if e.ID == replacing {
			continue
		}
		if (rec.Type == typeCNAME) != (e.Record.Type == typeCNAME) {
			return rec, fail(http.StatusBadRequest, "invalid argument: a CNAME record must be unique at its name")
		}
	}
	return rec, nil
}

// uncheckedURI is why tsigoat turns down the URI records at Scaleway.
const uncheckedURI = "tsigoat did not check that Scaleway keeps URI records intact"

// Rejected returns the cases of the conformance suite of the backends that
// the scaleway backend turns down, with the reason, for the simulated API and
// for Scaleway itself.
func Rejected() map[string]string {
	return map[string]string{
		"types/DS":                  "tsigoat did not check that Scaleway keeps DS records intact",
		"types/HINFO":               "tsigoat did not check that Scaleway keeps HINFO records intact",
		"types/LOC":                 "tsigoat did not check that Scaleway keeps LOC records intact",
		"types/PTR":                 "Scaleway may hold no PTR record",
		"types/RP":                  "tsigoat did not check that Scaleway keeps RP records intact",
		"types/URI":                 uncheckedURI,
		"types/NS":                  "Scaleway gives NS records a TTL of 1800 at least",
		"txt/padded":                "Scaleway trims the spaces at the ends of TXT records",
		"txt/quote":                 "Scaleway mangles the quotes of TXT strings",
		"txt/backslash":             "Scaleway mangles the backslashes of TXT strings",
		"types/NAPTR-backreference": "tsigoat did not check that Scaleway keeps the backslashes of NAPTR records intact",
		"txt/utf8":                  "tsigoat keeps TXT strings to printable ASCII",
		"txt/strings":               "Scaleway holds a TXT record as a single string",
		"txt/empty":                 "Scaleway holds no empty TXT record",
		"ttl/zero":                  "Scaleway holds no TTL below 60",
		"apex/soa":                  "Scaleway manages the SOA record",
		"apex/ns":                   "Scaleway manages the NS records of the apex",
	}
}

// Failing returns a change that Scaleway fails, for the conformance suite: a
// CNAME record beside other data.
func Failing(name string) backend.Change {
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "target.example.net."}
	return backend.Change{Op: backend.Replace, RRset: backend.RRset{Name: name, Type: dns.TypeCNAME, TTL: 300, Records: []dns.RR{cname}}}
}

// Divergences returns the scenarios of test/scenario that fail on the
// simulated API on purpose, with the reason.
func Divergences() map[string]string {
	return map[string]string{
		"policy/soa-rule":              "Scaleway manages the SOA record: tsigoat turns its changes down",
		"records/ds":                   "tsigoat did not check that Scaleway keeps DS records intact",
		"records/hinfo":                "tsigoat did not check that Scaleway keeps HINFO records intact",
		"records/loc":                  "tsigoat did not check that Scaleway keeps LOC records intact",
		"records/ptr":                  "Scaleway may hold no PTR record",
		"records/uri":                  uncheckedURI,
		"records/uri-backslash":        uncheckedURI,
		"records/caa-backslash":        "tsigoat did not check that Scaleway keeps the backslashes of CAA records",
		"records/ttl-zero":             "Scaleway holds no TTL below 60: tsigoat raises it",
		"records/txt-escaped-quotes":   "Scaleway mangles the quotes of TXT strings: tsigoat turns them down",
		"records/txt-multiple-strings": "Scaleway holds a TXT record as a single string: tsigoat turns down the strings that it would join",
		"records/txt-utf8":             "tsigoat keeps TXT strings to printable ASCII",
	}
}

// waitingRequests returns the number of held requests that wait for their
// client to give up.
func (a *API) waitingRequests() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.waiting
}
