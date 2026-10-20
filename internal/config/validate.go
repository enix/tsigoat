package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// PowerDNS defaults.
const (
	defaultPowerDNSServerID = "localhost"
	defaultPowerDNSTimeout  = 5 * time.Second
	maxPowerDNSTimeout      = time.Minute
)

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
		k := &raw[i]

		name, nameOK := v.domainName(path+".name", k.Name)
		if nameOK {
			if previous, duplicate := seen[name]; duplicate {
				v.errorf(path+".name", "duplicate key %q, already defined by %s", name, previous)
			}
			seen[name] = path
		}

		algorithm := v.algorithm(path+".algorithm", k.Algorithm)
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

		keys = append(keys, Key{Name: name, Algorithm: algorithm, Secret: secret})
	}
	return keys
}

// algorithm validates a TSIG algorithm; HMAC-SHA256 when empty.
func (v *validator) algorithm(path, name string) Algorithm {
	if name == "" {
		return HMACSHA256
	}
	algorithm := Algorithm(strings.ToLower(name))
	switch algorithm {
	case HMACSHA256, HMACSHA384, HMACSHA512, HMACSHA224:
	case HMACSHA1:
		v.warnf(path, "RFC 8945 recommends against HMAC-SHA1: switch the clients of this key to hmac-sha256")
	case HMACMD5:
		v.warnf(path, "RFC 8945 forbids HMAC-MD5: keep it only for clients that cannot switch to hmac-sha256")
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

		backend := Backend{Name: b.Name, Type: b.Type}
		switch b.Type {
		case "powerdns":
			if b.PowerDNS == nil {
				v.errorf(path+".powerdns", "missing the settings of the powerdns backend")
			} else {
				backend.PowerDNS = v.powerDNS(path+".powerdns", b.PowerDNS)
			}
		case "":
			v.errorf(path+".type", "missing type (expected powerdns)")
		default:
			v.errorf(path+".type", "unknown type %q (expected powerdns)", b.Type)
		}
		backends = append(backends, backend)
	}
	return backends
}

func (v *validator) powerDNS(path string, raw *filePowerDNS) *PowerDNS {
	p := &PowerDNS{
		URL:      strings.TrimRight(raw.URL, "/"),
		ServerID: raw.ServerID,
		Timeout:  defaultPowerDNSTimeout,
		CAFile:   raw.CAFile,
	}
	if p.ServerID == "" {
		p.ServerID = defaultPowerDNSServerID
	}

	if u, err := url.Parse(raw.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		v.errorf(path+".url", "invalid URL %q: expected http(s)://host[:port]", raw.URL)
	}
	if apiKey, ok := v.secret(path, "apiKey", raw.APIKey, raw.APIKeyFile, raw.APIKeyEnv); ok {
		p.APIKey = apiKey
	}
	if raw.Timeout != "" {
		timeout, err := time.ParseDuration(raw.Timeout)
		switch {
		case err != nil:
			v.errorf(path+".timeout", "invalid duration %q", raw.Timeout)
		case timeout <= 0 || timeout > maxPowerDNSTimeout:
			v.errorf(path+".timeout", "%s is out of range (0s, %s]", timeout, maxPowerDNSTimeout)
		default:
			p.Timeout = timeout
		}
	}
	if raw.CAFile != "" {
		if _, err := v.options.ReadFile(raw.CAFile); err != nil {
			v.errorf(path+".caFile", "%v", err)
		}
	}
	return p
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

		if len(r.Names) == 0 {
			v.errorf(rulePath+".names", "missing names")
		}
		for j, pattern := range r.Names {
			if canonical, ok := v.namePattern(fmt.Sprintf("%s.names[%d]", rulePath, j), pattern, zone); ok {
				rule.Names = append(rule.Names, canonical)
			}
		}

		for j, name := range r.Types {
			upper := strings.ToUpper(name)
			if _, ok := dns.StringToType[upper]; !ok {
				v.errorf(fmt.Sprintf("%s.types[%d]", rulePath, j), "unknown record type %q", name)
				continue
			}
			rule.Types = append(rule.Types, upper)
		}
		rules = append(rules, rule)
	}
	return rules
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
