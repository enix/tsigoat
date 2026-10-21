// Package ovhtest simulates the parts of the API of OVHcloud that the ovh
// backend calls, with the behaviors that matter to it: the signatures and the
// clock of the API, OAuth2 tokens, records with identifiers that change one
// request at a time, a name filter in SQL LIKE without regard to case, the
// publication of a zone by its refresh alone, the TXT targets that it quotes,
// and the TTLs below 60 that it raises silently.
package ovhtest

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: the signature of the OVHcloud API is SHA-1
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/hosted/hostedtest"
)

// The credentials that the simulated API accepts.
const (
	ApplicationKey    = "test-application-key"
	ApplicationSecret = "test-application-secret" // gitleaks:allow (fixture)
	ConsumerKey       = "test-consumer-key"       // gitleaks:allow (fixture)
	ClientID          = "test-client"
	ClientSecret      = "test-client-secret" // gitleaks:allow (fixture)
)

// TokenPath is the path of the OAuth2 token endpoint of the simulated API.
const TokenPath = "/auth/oauth2/token" //nolint:gosec // G101: a path, not a credential

// Record is a record of the API.
type Record struct {
	ID        int64  `json:"id"`
	FieldType string `json:"fieldType"`
	SubDomain string `json:"subDomain"`
	Target    string `json:"target"`
	TTL       uint32 `json:"ttl"`
	Zone      string `json:"zone"`
}

// API is a simulated API of OVHcloud.
type API struct {
	URL   string
	store *hostedtest.Store[Record]

	mu sync.Mutex
	// skew is the difference between the clock of the API and the local one.
	skew time.Duration
	// published holds the records of every zone at its last refresh.
	published map[string][]Record
	refreshes int
	// failures holds the outcomes of the next write requests.
	failures []Failure
	// late holds the requests that Late failures keep for Land; waiting
	// counts those that wait for their client to give up.
	late    []lateRequest
	waiting int
	tokens  int
}

// Failure is the outcome of a write request, refreshes included.
type Failure struct {
	// Status is the status of the error response; 0 lets the request
	// through.
	Status  int
	Message string
	// AfterCommit applies the request before answering the error, as a
	// request whose response is lost.
	AfterCommit bool
	// Late holds the request until the client gives up on it, then keeps
	// it, not applied, until Land applies it: a request that still applies
	// after its timeout.
	Late bool
}

// New starts a simulated API until the end of the test.
func New(t *testing.T) *API {
	t.Helper()
	a := &API{store: hostedtest.NewStore[Record](), published: map[string][]Record{}}
	server := httptest.NewServer(a)
	t.Cleanup(server.Close)
	a.URL = server.URL
	return a
}

// CreateZone creates or empties a zone, with the NS records of its apex and
// the records, then publishes it.
func (a *API) CreateZone(zone string, records ...dns.RR) {
	zone = strings.TrimSuffix(dns.CanonicalName(zone), ".")
	held := make([]Record, 0, 2+len(records))
	held = append(held,
		Record{FieldType: "NS", Target: "dns1.example.net.", TTL: 0, Zone: zone},
		Record{FieldType: "NS", Target: "ns1.example.net.", TTL: 0, Zone: zone},
	)
	for _, rr := range records {
		held = append(held, FromRR(rr, zone))
	}
	a.store.SetZone(zone, held...)
	a.publish(zone)
}

// FromRR returns a record of a zone as the API stores it.
func FromRR(rr dns.RR, zone string) Record {
	h := rr.Header()
	name := strings.TrimSuffix(dns.CanonicalName(h.Name), ".")
	sub := strings.TrimSuffix(strings.TrimSuffix(name, zone), ".")
	r := Record{FieldType: dns.Type(h.Rrtype).String(), SubDomain: sub, Target: backend.RData(rr), TTL: h.Ttl, Zone: zone}
	if r.TTL < 60 {
		r.TTL = 60
	}
	return r
}

// AddRaw adds a record as another client of the API would have stored it,
// such as an SPF record of OVHcloud, or an unquoted TXT target.
func (a *API) AddRaw(zone string, r *Record) {
	zone = strings.TrimSuffix(zone, ".")
	added := *r
	added.Zone = zone
	_ = a.store.Update(zone, func(tx *hostedtest.Tx[Record]) error {
		tx.Create(added)
		return nil
	})
}

// Records returns the records of a zone, as they stand.
func (a *API) Records(zone string) []Record {
	entries, _ := a.store.Records(strings.TrimSuffix(zone, "."), nil)
	records := make([]Record, 0, len(entries))
	for _, e := range entries {
		r := e.Record
		r.ID, _ = strconv.ParseInt(e.ID, 10, 64)
		records = append(records, r)
	}
	return records
}

// Published returns the records of a zone at its last refresh, which its
// name servers serve.
func (a *API) Published(zone string) []Record {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.published[strings.TrimSuffix(zone, ".")])
}

// Refreshes returns the number of refreshes.
func (a *API) Refreshes() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.refreshes
}

// Tokens returns the number of OAuth2 tokens issued.
func (a *API) Tokens() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tokens
}

// SetSkew sets the difference between the clock of the API and the local
// one.
func (a *API) SetSkew(skew time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.skew = skew
}

// lateRequest is a request that applies after its client gave up on it.
type lateRequest struct {
	r     *http.Request
	parts []string
	body  []byte
}

// Waiting returns the number of requests that Late failures hold, which wait
// for their client to give up.
func (a *API) Waiting() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.waiting
}

// Land applies the requests that Late failures kept, as their late
// application by OVHcloud, once none waits for its client to give up: the
// server learns it after the client.
func (a *API) Land() {
	for deadline := time.Now().Add(5 * time.Second); a.Waiting() > 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	a.mu.Lock()
	late := a.late
	a.late = nil
	a.mu.Unlock()
	for _, l := range late {
		a.zone(httptest.NewRecorder(), l.r, l.parts, l.body)
	}
}

// FailWrites sets the outcomes of the next write requests, refreshes
// included.
func (a *API) FailWrites(failures ...Failure) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failures = append(a.failures, failures...)
}

func (a *API) publish(zone string) {
	entries, _ := a.store.Records(zone, nil)
	records := make([]Record, 0, len(entries))
	for _, e := range entries {
		r := e.Record
		r.ID, _ = strconv.ParseInt(e.ID, 10, 64)
		records = append(records, r)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.published[zone] = records
	a.refreshes++
}

// errorBody writes an error response as the API does.
func errorBody(w http.ResponseWriter, status int, class, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Ovh-Queryid", "EU.ext-1.test")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"class": class, "message": message})
}

func reply(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Ovh-Queryid", "EU.ext-1.test")
	_ = json.NewEncoder(w).Encode(body)
}

// ServeHTTP serves the API.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/auth/time":
		a.mu.Lock()
		now := time.Now().Add(a.skew)
		a.mu.Unlock()
		reply(w, now.Unix())
		return
	case r.Method == http.MethodPost && r.URL.Path == TokenPath:
		a.token(w, r, body)
		return
	}
	if status, class, message := a.authenticate(r, body); status != 0 {
		errorBody(w, status, class, message)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, zonePrefix), "/")
	if !strings.HasPrefix(r.URL.Path, zonePrefix) || !a.store.HasZone(parts[0]) {
		errorBody(w, http.StatusNotFound, classNotFound, "This service does not exist")
		return
	}
	if r.Method != http.MethodGet && a.fail(w, r, parts, body) {
		return
	}
	a.zone(w, r, parts, body)
}

// fail plays the next failure of a write request, and reports whether there
// was one.
func (a *API) fail(w http.ResponseWriter, r *http.Request, parts []string, body []byte) bool {
	f := a.nextFailure()
	switch {
	case f.Late:
		a.mu.Lock()
		a.waiting++
		a.mu.Unlock()
		<-r.Context().Done()
		a.mu.Lock()
		a.waiting--
		a.late = append(a.late, lateRequest{r: r.Clone(context.WithoutCancel(r.Context())), parts: parts, body: body})
		a.mu.Unlock()
		return true
	case f.Status != 0:
		if f.AfterCommit {
			a.zone(httptest.NewRecorder(), r, parts, body)
		}
		errorBody(w, f.Status, "Server::InternalServerError", f.Message)
		return true
	}
	return false
}

// The prefix of the paths of the zones, and the class of the errors of a
// missing object.
const (
	zonePrefix    = "/domain/zone/"
	classNotFound = "Client::NotFound"
)

// zone serves the requests on a zone.
func (a *API) zone(w http.ResponseWriter, r *http.Request, parts []string, body []byte) {
	zone := parts[0]
	switch {
	case len(parts) == 2 && parts[1] == "soa" && r.Method == http.MethodGet:
		reply(w, map[string]any{
			"server": "dns1.example.net", "email": "tech@example.net", "serial": 2026102001,
			"refresh": 86400, "expire": 3600000, "nxDomainTtl": 60, "ttl": 3600,
		})
	case len(parts) == 2 && parts[1] == "refresh" && r.Method == http.MethodPost:
		a.publish(zone)
		reply(w, nil)
	case len(parts) == 2 && parts[1] == "record":
		a.collection(w, r, zone, body)
	case len(parts) == 3 && parts[1] == "record":
		a.member(w, r, zone, parts[2], body)
	default:
		errorBody(w, http.StatusNotFound, classNotFound, "Got an invalid (or empty) URL")
	}
}

func (a *API) nextFailure() Failure {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.failures) == 0 {
		return Failure{}
	}
	f := a.failures[0]
	a.failures = a.failures[1:]
	return f
}

// authenticate checks the signature or the bearer token of a request, and
// returns the error response, a status of 0 when the request is fine.
func (a *API) authenticate(r *http.Request, body []byte) (status int, class, message string) {
	if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		if bearer != "token-"+ClientID {
			return http.StatusUnauthorized, "Client::Unauthorized", "You must login first"
		}
		return 0, "", ""
	}
	if r.Header.Get("X-Ovh-Application") != ApplicationKey {
		return http.StatusForbidden, "Client::Forbidden", "This application key is invalid"
	}
	timestamp, err := strconv.ParseInt(r.Header.Get("X-Ovh-Timestamp"), 10, 64)
	a.mu.Lock()
	now := time.Now().Add(a.skew).Unix()
	a.mu.Unlock()
	if err != nil || timestamp < now-120 || timestamp > now+120 {
		return http.StatusBadRequest, "Client::BadRequest", "Query out of time"
	}
	target := "http://" + r.Host + r.URL.RequestURI()
	digest := sha1.Sum([]byte(strings.Join([]string{ //nolint:gosec // G401: the signature of the OVHcloud API is SHA-1
		ApplicationSecret, r.Header.Get("X-Ovh-Consumer"), r.Method, target, string(body), r.Header.Get("X-Ovh-Timestamp"),
	}, "+")))
	if r.Header.Get("X-Ovh-Consumer") != ConsumerKey || r.Header.Get("X-Ovh-Signature") != "$1$"+hex.EncodeToString(digest[:]) {
		return http.StatusForbidden, "Client::Forbidden", "Invalid signature"
	}
	return 0, "", ""
}

// token issues an OAuth2 access token for the client credentials.
func (a *API) token(w http.ResponseWriter, r *http.Request, body []byte) {
	id, secret, ok := r.BasicAuth()
	form, err := url.ParseQuery(string(body))
	if !ok || err != nil || id != ClientID || secret != ClientSecret || form.Get("grant_type") != "client_credentials" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		return
	}
	a.mu.Lock()
	a.tokens++
	a.mu.Unlock()
	reply(w, map[string]any{"access_token": "token-" + ClientID, "token_type": "Bearer", "expires_in": 3599, "scope": "all"})
}

// like reports whether a value matches a pattern of SQL LIKE without regard
// to case: "%" matches any string, "_" any character.
func like(value, pattern string) bool {
	expression := "(?is)^" + strings.NewReplacer("%", ".*", "_", ".").Replace(regexp.QuoteMeta(pattern)) + "$"
	matched, _ := regexp.MatchString(expression, value)
	return matched
}

func (a *API) collection(w http.ResponseWriter, r *http.Request, zone string, body []byte) {
	if r.Method == http.MethodGet {
		query := r.URL.Query()
		entries, _ := a.store.Records(zone, func(rec Record) bool {
			return (!query.Has("subDomain") || like(rec.SubDomain, query.Get("subDomain"))) &&
				(query.Get("fieldType") == "" || rec.FieldType == query.Get("fieldType"))
		})
		ids := make([]int64, 0, len(entries))
		for _, e := range entries {
			id, _ := strconv.ParseInt(e.ID, 10, 64)
			ids = append(ids, id)
		}
		reply(w, ids)
		return
	}
	var create Record
	if err := json.Unmarshal(body, &create); err != nil || r.Method != http.MethodPost {
		errorBody(w, http.StatusBadRequest, "Client::BadRequest", "Invalid request")
		return
	}
	rec, message := normalize(&create, zone)
	if message != "" {
		errorBody(w, http.StatusBadRequest, "Client::BadRequest", message)
		return
	}
	var id string
	_ = a.store.Update(zone, func(tx *hostedtest.Tx[Record]) error {
		id = tx.Create(rec)
		return nil
	})
	rec.ID, _ = strconv.ParseInt(id, 10, 64)
	reply(w, rec)
}

func (a *API) member(w http.ResponseWriter, r *http.Request, zone, id string, body []byte) {
	err := a.store.Update(zone, func(tx *hostedtest.Tx[Record]) error {
		rec, err := tx.Get(id)
		if err != nil {
			return err
		}
		switch r.Method {
		case http.MethodGet:
			rec.ID, _ = strconv.ParseInt(id, 10, 64)
			reply(w, rec)
		case http.MethodDelete:
			reply(w, nil)
			return tx.Delete(id)
		case http.MethodPut:
			var update map[string]any
			if decodeErr := json.Unmarshal(body, &update); decodeErr != nil || update["fieldType"] != nil {
				errorBody(w, http.StatusBadRequest, "Client::BadRequest", "Try to alter read-only properties: fieldType")
				return nil //nolint:nilerr // the response tells the error, and the transaction changes nothing
			}
			if ttl, ok := update["ttl"].(float64); ok {
				rec.TTL = max(uint32(ttl), 60)
			}
			reply(w, nil)
			return tx.Put(id, rec)
		}
		return nil
	})
	if err != nil {
		errorBody(w, http.StatusNotFound, classNotFound, fmt.Sprintf("The requested object (id = %s) does not exist", id))
	}
}

// fieldTypes lists the types that the API accepts.
func fieldTypes() []string {
	return []string{
		"A", "AAAA", "CAA", "CNAME", "DKIM", "DMARC", "DNAME", "HTTPS", "LOC", "MX", "NAPTR", "NS", "PTR", "RP",
		"SPF", "SRV", "SSHFP", "SVCB", "TLSA", "TXT",
	}
}

// normalize checks a new record as the API does, and returns it as the API
// stores it, or the message of the error.
func normalize(created *Record, zone string) (rec Record, message string) {
	rec = *created
	rec.ID, rec.Zone = 0, zone
	switch {
	case !slices.Contains(fieldTypes(), rec.FieldType):
		return rec, "Invalid field type " + rec.FieldType
	case strings.HasPrefix(rec.SubDomain, "__"):
		return rec, fmt.Sprintf("Invalid record ResourceRecord(zone=%s, sub_domain='%s')", zone, rec.SubDomain)
	case rec.TTL != 0 && rec.TTL < 60:
		// Silently.
		rec.TTL = 60
	}
	switch rec.FieldType {
	case "TXT", "SPF":
		rec.Target = strings.TrimRight(rec.Target, " ")
		if !strings.HasPrefix(rec.Target, `"`) {
			rec.Target = `"` + rec.Target + `"`
		}
	case "CAA":
		if !regexp.MustCompile(`^\d+ \S+ ".*"$`).MatchString(rec.Target) {
			return rec, "Invalid target for CAA record"
		}
	case "MX", "SRV", "DNAME", "RP", "SVCB", "HTTPS":
		fields := strings.Fields(rec.Target)
		for _, field := range fields {
			if strings.Contains(field, "_") && strings.Contains(field, ".") && !strings.Contains(field, "=") {
				return rec, "Invalid domain name, underscore not allowed"
			}
		}
	}
	return rec, ""
}

// noURI is why OVHcloud turns down the URI records.
const noURI = "OVHcloud holds no URI record"

// Rejected returns the cases of the conformance suite of the backends that
// the ovh backend turns down, with the reason, for the simulated API and for
// OVHcloud itself.
func Rejected() map[string]string {
	return map[string]string{
		"types/DS":                  "OVHcloud holds no DS record",
		"types/HINFO":               "OVHcloud holds no HINFO record",
		"types/URI":                 noURI,
		"txt/padded":                "OVHcloud trims the spaces at the ends of TXT strings",
		"txt/quote":                 "OVHcloud mangles the quotes of TXT strings",
		"txt/backslash":             "OVHcloud mangles the backslashes of TXT strings",
		"types/NAPTR-backreference": "tsigoat did not check that OVHcloud keeps the backslashes of NAPTR records intact",
		"txt/utf8":                  "tsigoat keeps TXT strings to printable ASCII",
		"txt/empty":                 "OVHcloud holds no empty TXT string",
		"ttl/zero":                  "OVHcloud holds no TTL below 60",
		"apex/soa":                  "OVHcloud manages the SOA record",
		"apex/ns":                   "OVHcloud manages the NS records of the apex",
	}
}

// Failing returns a change that OVHcloud fails, for the conformance suite: an
// MX record whose exchange holds an underscore.
func Failing(name string) backend.Change {
	mx := &dns.MX{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 10, Mx: "mail_server.example.net."}
	return backend.Change{Op: backend.Replace, RRset: backend.RRset{Name: name, Type: dns.TypeMX, TTL: 300, Records: []dns.RR{mx}}}
}

// Divergences returns the scenarios of test/scenario that fail on the
// simulated API on purpose, with the reason.
func Divergences() map[string]string {
	return map[string]string{
		"records/ds":                 "OVHcloud holds no DS record",
		"records/hinfo":              "OVHcloud holds no HINFO record",
		"records/uri":                noURI,
		"records/uri-backslash":      noURI,
		"records/caa-backslash":      "tsigoat did not check that OVHcloud keeps the backslashes of CAA records",
		"records/ttl-zero":           "OVHcloud holds no TTL below 60: tsigoat raises it",
		"records/txt-escaped-quotes": "OVHcloud mangles the quotes of TXT strings: tsigoat turns them down",
		"records/txt-utf8":           "tsigoat keeps TXT strings to printable ASCII",
	}
}
