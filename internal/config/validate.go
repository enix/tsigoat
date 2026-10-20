package config

import (
	"encoding/base64"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Backend defaults.
const (
	defaultPowerDNSServerID = "localhost"
	// defaultBackendTimeout bounds every call to a backend, up to
	// maxBackendTimeout.
	defaultBackendTimeout = 5 * time.Second
	maxBackendTimeout     = time.Minute
)

// Bounds of the policy rules.
const (
	// maxTTL is the largest TTL, 2^31 - 1 seconds (RFC 2181 8).
	maxTTL = 1<<31 - 1
	// ACME rules bound the records to what the clients need: a TTL of a few
	// minutes, a few challenge values per update.
	defaultACMEMaxTTL     = 300
	defaultACMEMaxRecords = 10
	// txtType is the type of the records of ACME challenges.
	txtType = "TXT"
	// httpScheme and httpsScheme are the schemes of the URLs of the backends.
	httpScheme  = "http"
	httpsScheme = "https"
)

// keyHolder tells who shares a TSIG key with tsigoat, for the advice of the
// warnings about legacy algorithms.
type keyHolder int

const (
	// clientKey is a key that clients sign their requests with.
	clientKey keyHolder = iota
	// serverKey is the key that tsigoat signs with for a name server.
	serverKey
)

// legacyAdvice tells what to do about a key with HMAC-SHA1, and with
// HMAC-MD5.
func (h keyHolder) legacyAdvice() (sha1, md5 string) {
	if h == serverKey {
		return "switch the name server and this key to hmac-sha256",
			"keep it only for a name server that cannot switch to hmac-sha256"
	}
	return "switch the clients of this key to hmac-sha256",
		"keep it only for clients that cannot switch to hmac-sha256"
}

// validator turns the configuration as written into a validated Config,
// collecting every error and warning on the way.
type validator struct {
	options  Options
	errs     []error
	warnings []string
}

func (v *validator) errorf(path, format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf("%s: %s", path, fmt.Sprintf(format, args...)))
}

func (v *validator) warnf(path, format string, args ...any) {
	v.warnings = append(v.warnings, fmt.Sprintf("%s: %s", path, fmt.Sprintf(format, args...)))
}

func (v *validator) config(raw *file) *Config {
	c := &Config{
		Listen:   v.listen(raw.Listen),
		Keys:     v.keys(raw.Keys),
		Backends: v.backends(raw.Backends),
	}
	if raw.Admin != nil {
		c.AdminListen = v.adminListen(raw.Admin.Listen, c.Listen)
	}
	c.Zones = v.zones(raw.Zones, c)
	return c
}

// adminListen validates the address of the administration server, which
// cannot share a TCP address with the DNS listeners.
func (v *validator) adminListen(address string, dnsListen []string) string {
	const path = "admin.listen"
	if !v.hostPort(path, address) {
		return ""
	}
	if slices.Contains(dnsListen, address) {
		v.errorf(path, "address %q is also a DNS listen address", address)
	}
	return address
}

func (v *validator) listen(addresses []string) []string {
	if len(addresses) == 0 {
		return []string{DefaultListen}
	}
	seen := map[string]bool{}
	for i, address := range addresses {
		path := fmt.Sprintf("listen[%d]", i)
		if !v.hostPort(path, address) {
			continue
		}
		if seen[address] {
			v.errorf(path, "duplicate address %q", address)
		}
		seen[address] = true
	}
	return addresses
}

// hostPort validates a host:port address with a non-zero port.
func (v *validator) hostPort(path, address string) bool {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		v.errorf(path, "invalid address %q: expected host:port", address)
		return false
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		v.errorf(path, "invalid port %q", port)
		return false
	}
	return true
}

func (v *validator) keys(raw []fileKey) []Key {
	keys := make([]Key, 0, len(raw))
	seen := map[string]string{}
	for i := range raw {
		path := fmt.Sprintf("keys[%d]", i)
		k, nameOK := v.key(path, &raw[i], clientKey)
		if nameOK {
			if previous, duplicate := seen[k.Name]; duplicate {
				v.errorf(path+".name", "duplicate key %q, already defined by %s", k.Name, previous)
			}
			seen[k.Name] = path
		}
		keys = append(keys, k)
	}
	return keys
}

// key validates a TSIG key, and tells whether its name is valid.
func (v *validator) key(path string, k *fileKey, holder keyHolder) (Key, bool) {
	name, nameOK := v.domainName(path+".name", k.Name)
	algorithm := v.algorithm(path+".algorithm", k.Algorithm, holder)
	encoded, secretOK := v.secret(path, "secret", k.Secret, k.SecretFile, k.SecretEnv)
	var secret []byte
	if secretOK {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		switch {
		case err != nil:
			v.errorf(path+".secret", "not valid base64: %v", err)
		case len(decoded) == 0:
			v.errorf(path+".secret", "empty secret")
		case len(decoded) < algorithmSize(algorithm):
			v.warnf(path+".secret", "%d bytes is shorter than the %d-byte output of %s, as RFC 8945 advises against",
				len(decoded), algorithmSize(algorithm), algorithm)
		}
		secret = decoded
	}
	return Key{Name: name, Algorithm: algorithm, Secret: secret}, nameOK
}

// algorithm validates a TSIG algorithm; HMAC-SHA256 when empty.
func (v *validator) algorithm(path, name string, holder keyHolder) Algorithm {
	if name == "" {
		return HMACSHA256
	}
	algorithm := Algorithm(strings.ToLower(name))
	sha1Advice, md5Advice := holder.legacyAdvice()
	switch algorithm {
	case HMACSHA256, HMACSHA384, HMACSHA512, HMACSHA224:
	case HMACSHA1:
		v.warnf(path, "RFC 8945 recommends against HMAC-SHA1: %s", sha1Advice)
	case HMACMD5:
		v.warnf(path, "RFC 8945 forbids HMAC-MD5: %s", md5Advice)
	default:
		v.errorf(path, "unknown algorithm %q (expected hmac-sha256, hmac-sha384, hmac-sha512, hmac-sha224, "+
			"or the legacy hmac-sha1 and hmac-md5)", name)
	}
	return algorithm
}

// algorithmSize returns the output size of an HMAC algorithm, in bytes.
func algorithmSize(algorithm Algorithm) int {
	switch algorithm {
	case HMACSHA512:
		return 64
	case HMACSHA384:
		return 48
	case HMACSHA256:
		return 32
	case HMACSHA224:
		return 28
	case HMACSHA1:
		return 20
	case HMACMD5:
		return 16
	default:
		return 0
	}
}

// secret resolves a secret written inline, read from a file or from an
// environment variable. Exactly one source must be set.
func (v *validator) secret(path, field, inline, fromFile, fromEnv string) (string, bool) {
	sources := 0
	for _, source := range []string{inline, fromFile, fromEnv} {
		if source != "" {
			sources++
		}
	}
	switch {
	case sources == 0:
		v.errorf(path, "missing %[1]s: set %[1]s, %[1]sFile or %[1]sEnv", field)
		return "", false
	case sources > 1:
		v.errorf(path, "set only one of %[1]s, %[1]sFile and %[1]sEnv", field)
		return "", false
	case fromFile != "":
		data, err := v.options.ReadFile(fromFile)
		if err != nil {
			v.errorf(path+"."+field+"File", "%v", err)
			return "", false
		}
		return strings.TrimSpace(string(data)), true
	case fromEnv != "":
		value, ok := v.options.LookupEnv(fromEnv)
		if !ok || value == "" {
			v.errorf(path+"."+field+"Env", "environment variable %s is not set", fromEnv)
			return "", false
		}
		return strings.TrimSpace(value), true
	default:
		return inline, true
	}
}

func (v *validator) backends(raw []fileBackend) []Backend {
	backends := make([]Backend, 0, len(raw))
	seen := map[string]string{}
	for i := range raw {
		path := fmt.Sprintf("backends[%d]", i)
		b := &raw[i]

		if b.Name == "" {
			v.errorf(path+".name", "missing name")
		} else {
			if previous, duplicate := seen[b.Name]; duplicate {
				v.errorf(path+".name", "duplicate backend %q, already defined by %s", b.Name, previous)
			}
			seen[b.Name] = path
		}

		backends = append(backends, v.backend(path, b))
	}
	return backends
}

// backend validates the type of a backend and its settings, which must match.
func (v *validator) backend(path string, b *fileBackend) Backend {
	backend := Backend{Name: b.Name, Type: b.Type}
	settings := map[string]bool{"powerdns": b.PowerDNS != nil, "rfc2136": b.RFC2136 != nil, "webhook": b.Webhook != nil}
	switch b.Type {
	case "powerdns":
		if b.PowerDNS != nil {
			backend.PowerDNS = v.powerDNS(path+".powerdns", b.PowerDNS)
		}
	case "rfc2136":
		if b.RFC2136 != nil {
			backend.RFC2136 = v.rfc2136(path+".rfc2136", b.RFC2136)
		}
	case "webhook":
		if b.Webhook != nil {
			backend.Webhook = v.webhook(path+".webhook", b.Webhook)
		}
	case "":
		v.errorf(path+".type", "missing type (expected powerdns, rfc2136 or webhook)")
		return backend
	default:
		v.errorf(path+".type", "unknown type %q (expected powerdns, rfc2136 or webhook)", b.Type)
		return backend
	}
	for _, section := range slices.Sorted(maps.Keys(settings)) {
		switch {
		case section == b.Type && !settings[section]:
			v.errorf(path+"."+section, "missing the settings of the %s backend", section)
		case section != b.Type && settings[section]:
			v.errorf(path+"."+section, "%s settings on a backend of type %s", section, b.Type)
		}
	}
	return backend
}

func (v *validator) powerDNS(path string, raw *filePowerDNS) *PowerDNS {
	p := &PowerDNS{
		URL:      strings.TrimRight(raw.URL, "/"),
		ServerID: raw.ServerID,
		Timeout:  v.backendTimeout(path+".timeout", raw.Timeout),
		CAFile:   raw.CAFile,
	}
	if p.ServerID == "" {
		p.ServerID = defaultPowerDNSServerID
	}

	if u, err := url.Parse(raw.URL); err != nil || (u.Scheme != httpScheme && u.Scheme != httpsScheme) || u.Host == "" {
		v.errorf(path+".url", "invalid URL %q: expected http(s)://host[:port]", raw.URL)
	}
	if apiKey, ok := v.secret(path, "apiKey", raw.APIKey, raw.APIKeyFile, raw.APIKeyEnv); ok {
		p.APIKey = apiKey
	}
	if raw.CAFile != "" {
		if _, err := v.options.ReadFile(raw.CAFile); err != nil {
			v.errorf(path+".caFile", "%v", err)
		}
	}
	return p
}

func (v *validator) rfc2136(path string, raw *fileRFC2136) *RFC2136 {
	r := &RFC2136{
		Server:  raw.Server,
		Timeout: v.backendTimeout(path+".timeout", raw.Timeout),
	}
	if raw.Server == "" {
		v.errorf(path+".server", "missing server: the host:port of the name server")
	} else {
		v.hostPort(path+".server", raw.Server)
	}
	if raw.Key == nil {
		v.errorf(path+".key", "missing key: the TSIG key that tsigoat signs with, which the name server accepts")
	} else {
		r.Key, _ = v.key(path+".key", raw.Key, serverKey)
	}
	return r
}

// webhook validates the settings of a webhook backend, and warns about the
// settings that expose the requests.
func (v *validator) webhook(path string, raw *fileWebhook) *Webhook {
	w := &Webhook{
		URL:                raw.URL,
		Timeout:            v.backendTimeout(path+".timeout", raw.Timeout),
		CAFile:             raw.CAFile,
		InsecureSkipVerify: raw.InsecureSkipVerify,
		FollowRedirects:    raw.FollowRedirects,
	}
	u, err := url.Parse(raw.URL)
	if err != nil || (u.Scheme != httpScheme && u.Scheme != httpsScheme) || u.Host == "" {
		v.errorf(path+".url", "invalid URL %q: expected http(s)://host[:port][/path]", raw.URL)
	}
	if raw.CAFile != "" {
		if _, readErr := v.options.ReadFile(raw.CAFile); readErr != nil {
			v.errorf(path+".caFile", "%v", readErr)
		}
	}
	v.webhookAuthentication(path, raw, w)
	v.webhookHeaders(path, raw, w)
	v.webhookWarnings(path, w, u != nil && u.Scheme == httpScheme)
	return w
}

// webhookWarnings warns about the settings of a webhook that expose its
// requests.
func (v *validator) webhookWarnings(path string, w *Webhook, plainHTTP bool) {
	credentials := w.Username != "" || w.BearerToken != ""
	switch {
	case w.SignatureSecret == "" && !credentials:
		v.warnf(path, "the requests carry neither a signature nor credentials: the endpoint must authenticate them otherwise")
	case credentials && plainHTTP:
		v.warnf(path, "sends its credentials in clear text over http")
	}
	if w.InsecureSkipVerify {
		exposure := "read the requests"
		if credentials {
			exposure += ", steal the credentials"
		}
		if w.SignatureSecret == "" {
			exposure += " and change the requests"
		}
		v.warnf(path+".insecureSkipVerify", "accepts any certificate: someone in the middle may %s", exposure)
	}
}

// validHeaderName reports whether a header name is a token of RFC 9110
// 5.6.2.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		isAlphanumeric := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !isAlphanumeric && !strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			return false
		}
	}
	return true
}

// webhookAuthentication validates the signature and the credentials of a
// webhook: basic authentication and a bearer token both take the
// Authorization header.
func (v *validator) webhookAuthentication(path string, raw *fileWebhook, w *Webhook) {
	if s := raw.Signature; s != nil {
		if secret, ok := v.secret(path+".signature", "secret", s.Secret, s.SecretFile, s.SecretEnv); ok {
			w.SignatureSecret = secret
		}
	}
	if raw.BasicAuth != nil && raw.Bearer != nil {
		v.errorf(path+".bearer", "set basicAuth or bearer, not both: both take the Authorization header")
		return
	}
	if b := raw.BasicAuth; b != nil {
		if b.Username == "" || strings.Contains(b.Username, ":") {
			v.errorf(path+".basicAuth.username", "missing username, or one with a colon")
		}
		w.Username = b.Username
		if password, ok := v.secret(path+".basicAuth", "password", b.Password, b.PasswordFile, b.PasswordEnv); ok {
			w.Password = password
		}
	}
	if b := raw.Bearer; b != nil {
		if token, ok := v.secret(path+".bearer", "token", b.Token, b.TokenFile, b.TokenEnv); ok {
			w.BearerToken = token
		}
	}
}

// webhookHeaders validates the headers of a webhook, which may not take the
// place of those that tsigoat sets.
func (v *validator) webhookHeaders(path string, raw *fileWebhook, w *Webhook) {
	reserved := []string{
		"Connection", "Content-Length", "Content-Type", "Host", "Transfer-Encoding", "User-Agent",
		"X-Tsigoat-Signature", "X-Tsigoat-Timestamp",
	}
	if raw.BasicAuth != nil || raw.Bearer != nil {
		reserved = append(reserved, "Authorization")
	}
	seen := map[string]bool{}
	for i := range raw.Headers {
		itemPath := fmt.Sprintf("%s.headers[%d]", path, i)
		h := &raw.Headers[i]
		name := http.CanonicalHeaderKey(h.Name)
		switch {
		case !validHeaderName(h.Name):
			v.errorf(itemPath+".name", "invalid header name %q", h.Name)
		case slices.Contains(reserved, name):
			v.errorf(itemPath+".name", "tsigoat sets the %s header itself", name)
		case seen[name]:
			v.errorf(itemPath+".name", "duplicate header %s", name)
		}
		seen[name] = true
		value, ok := v.secret(itemPath, "value", h.Value, h.ValueFile, h.ValueEnv)
		if ok && strings.ContainsAny(value, "\r\n") {
			v.errorf(itemPath, "the value of header %s holds a line break", name)
			continue
		}
		w.Headers = append(w.Headers, Header{Name: name, Value: value})
	}
}

// backendTimeout validates the timeout of the calls to a backend;
// defaultBackendTimeout when empty.
func (v *validator) backendTimeout(path, raw string) time.Duration {
	if raw == "" {
		return defaultBackendTimeout
	}
	timeout, err := time.ParseDuration(raw)
	switch {
	case err != nil:
		v.errorf(path, "invalid duration %q", raw)
	case timeout <= 0 || timeout > maxBackendTimeout:
		v.errorf(path, "%s is out of range (0s, %s]", timeout, maxBackendTimeout)
	default:
		return timeout
	}
	return defaultBackendTimeout
}

func (v *validator) zones(raw []fileZone, c *Config) []Zone {
	if len(raw) == 0 {
		v.errorf("zones", "no zone configured")
		return nil
	}
	zones := make([]Zone, 0, len(raw))
	seen := map[string]string{}
	for i := range raw {
		path := fmt.Sprintf("zones[%d]", i)
		z := &raw[i]

		name, ok := v.domainName(path+".name", z.Name)
		if ok {
			if previous, duplicate := seen[name]; duplicate {
				v.errorf(path+".name", "duplicate zone %q, already defined by %s", name, previous)
			}
			seen[name] = path
		}

		zone := Zone{
			Name:                 name,
			Backend:              v.zoneBackend(path, z.Backend, c.Backends),
			AllowUnauthenticated: z.AllowUnauthenticated,
			Keys:                 v.keyReferences(path+".keys", z.Keys, c.Keys),
		}
		zone.Policy = v.policy(path+".policy", z.Policy, name, zone.Keys, c.Keys)

		if !zone.AllowUnauthenticated && len(zone.Keys) == 0 && len(zone.Policy) == 0 {
			v.errorf(path, "nothing may update this zone: set keys, policy or allowUnauthenticated")
		}
		if zone.AllowUnauthenticated {
			v.warnf(path, "accepts unauthenticated updates from anyone who can reach tsigoat")
		}
		zones = append(zones, zone)
	}
	return zones
}

func (v *validator) zoneBackend(path, name string, backends []Backend) string {
	switch {
	case name == "" && len(backends) == 1:
		return backends[0].Name
	case name == "":
		v.errorf(path+".backend", "missing backend (required unless exactly one backend is configured)")
	case !slices.ContainsFunc(backends, func(b Backend) bool { return b.Name == name }):
		v.errorf(path+".backend", "unknown backend %q", name)
	}
	return name
}

// keyReferences canonicalises key names and checks that they are defined.
func (v *validator) keyReferences(path string, names []string, keys []Key) []string {
	references := make([]string, 0, len(names))
	for i, raw := range names {
		itemPath := fmt.Sprintf("%s[%d]", path, i)
		name, ok := v.domainName(itemPath, raw)
		if !ok {
			continue
		}
		if !slices.ContainsFunc(keys, func(k Key) bool { return k.Name == name }) {
			v.errorf(itemPath, "unknown key %q", name)
			continue
		}
		references = append(references, name)
	}
	return references
}

func (v *validator) policy(path string, raw []fileRule, zone string, zoneKeys []string, keys []Key) []Rule {
	rules := make([]Rule, 0, len(raw))
	for i := range raw {
		rulePath := fmt.Sprintf("%s[%d]", path, i)
		r := &raw[i]

		rule := Rule{}
		if refs := v.keyReferences(rulePath+".key", []string{r.Key}, keys); len(refs) == 1 {
			rule.Key = refs[0]
			if slices.Contains(zoneKeys, rule.Key) {
				v.errorf(rulePath+".key", "key %q is also listed in keys, which already allows it everything", rule.Key)
			}
		}

		if len(r.ACME) > 0 {
			v.acmeRule(rulePath, r, zone, &rule)
		} else {
			v.namesAndTypes(rulePath, r, zone, &rule)
		}
		v.ruleBounds(rulePath, r, &rule)
		rules = append(rules, rule)
	}
	return rules
}

// namesAndTypes validates the names, the types and the content of a rule.
func (v *validator) namesAndTypes(path string, r *fileRule, zone string, rule *Rule) {
	if len(r.Names) == 0 {
		v.errorf(path+".names", "missing names, or acme for the challenges of ACME certificates")
	}
	for j, pattern := range r.Names {
		if canonical, ok := v.namePattern(fmt.Sprintf("%s.names[%d]", path, j), pattern, zone); ok {
			rule.Names = append(rule.Names, canonical)
		}
	}

	for j, name := range r.Types {
		upper := strings.ToUpper(name)
		if _, ok := dns.StringToType[upper]; !ok {
			v.errorf(fmt.Sprintf("%s.types[%d]", path, j), "unknown record type %q", name)
			continue
		}
		rule.Types = append(rule.Types, upper)
	}

	switch Content(r.Content) {
	case AnyContent:
	case ACMEContent:
		rule.Content = ACMEContent
		if len(r.Types) == 0 {
			rule.Types = []string{txtType}
		} else if !slices.Equal(rule.Types, []string{txtType}) {
			v.errorf(path+".types", "content acme only fits TXT records")
		}
	default:
		v.errorf(path+".content", "unknown content %q (expected acme)", r.Content)
	}
}

// acmeRule turns the certificate names of an acme rule into the names of
// their DNS-01 challenges (RFC 8555 8.4): _acme-challenge.example.com. for
// example.com. and for its wildcard *.example.com., and
// _acme-challenge.**.example.com. for every name below example.com. The rule
// allows the values of the challenges, and nothing else.
func (v *validator) acmeRule(path string, r *fileRule, zone string, rule *Rule) {
	if len(r.Names) > 0 || len(r.Types) > 0 || r.Content != "" {
		v.errorf(path, "acme sets the names, the types and the content of the rule: remove names, types and content")
	}
	rule.Types, rule.Content = []string{txtType}, ACMEContent
	for j, certificate := range r.ACME {
		entryPath := fmt.Sprintf("%s.acme[%d]", path, j)
		domain := strings.TrimPrefix(canonicalName(certificate), "*.")
		if certificate == "" || strings.Contains(strings.TrimPrefix(domain, "**."), "*") {
			v.errorf(entryPath, "invalid certificate name %q: expected a domain name, its wildcard *.domain, "+
				"or **.domain for every name below the domain", certificate)
			continue
		}
		challenge, ok := v.namePattern(entryPath, "_acme-challenge."+domain, zone)
		if ok && !slices.Contains(rule.Names, challenge) {
			rule.Names = append(rule.Names, challenge)
		}
	}
}

// ruleBounds validates the bounds of a rule on the records that an update
// adds: their TTL and their number. ACME rules have bounds by default.
func (v *validator) ruleBounds(path string, r *fileRule, rule *Rule) {
	acme := len(r.ACME) > 0
	switch {
	case r.MaxTTL != nil && (*r.MaxTTL < 1 || *r.MaxTTL > maxTTL):
		v.errorf(path+".maxTTL", "%d is out of range [1, %d]", *r.MaxTTL, maxTTL)
	case r.MaxTTL != nil:
		rule.MaxTTL = uint32(*r.MaxTTL) //nolint:gosec // G115: within [1, maxTTL], checked above
	case acme:
		rule.MaxTTL = defaultACMEMaxTTL
	}
	switch {
	case r.MaxRecords != nil && *r.MaxRecords < 1:
		v.errorf(path+".maxRecords", "%d is below 1", *r.MaxRecords)
	case r.MaxRecords != nil:
		rule.MaxRecords = *r.MaxRecords
	case acme:
		rule.MaxRecords = defaultACMEMaxRecords
	}
}

// namePattern validates a policy name pattern, which must lie inside the zone.
func (v *validator) namePattern(path, pattern, zone string) (string, bool) {
	canonical := canonicalName(pattern)
	if pattern == "" || !validName(canonical) {
		v.errorf(path, "invalid name pattern %q", pattern)
		return "", false
	}
	if zone != "" && canonical != zone && !strings.HasSuffix(canonical, "."+zone) {
		v.errorf(path, "name pattern %q is not inside zone %q", pattern, zone)
		return "", false
	}
	return canonical, true
}

// domainName validates and canonicalises a domain name.
func (v *validator) domainName(path, name string) (string, bool) {
	if name == "" {
		v.errorf(path, "missing name")
		return "", false
	}
	canonical := canonicalName(name)
	if canonical == "." || !validName(canonical) {
		v.errorf(path, "invalid domain name %q", name)
		return "", false
	}
	return canonical, true
}

// canonicalName returns the canonical form of a name: lower case, with a
// trailing dot.
func canonicalName(name string) string {
	return dns.CanonicalName(name)
}

func validName(name string) bool {
	_, ok := dns.IsDomainName(name)
	return ok && !strings.Contains(name, " ")
}
