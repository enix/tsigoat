package scenario

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Backend is the backend of every zone of the scenarios: PowerDNS or RFC2136.
type Backend interface {
	// entry returns the backend in the configuration of tsigoat.
	entry() backendEntry
}

// PowerDNS locates the PowerDNS API that tsigoat writes to.
type PowerDNS struct {
	URL    string
	APIKey string
	// Timeout of the calls to the API, such as "1s"; the default when empty.
	Timeout string
}

func (p PowerDNS) entry() backendEntry {
	return backendEntry{Name: "pdns", Type: "powerdns", PowerDNS: &powerDNSEntry{URL: p.URL, APIKey: p.APIKey, Timeout: p.Timeout}}
}

// RFC2136 locates a name server that tsigoat relays the updates to.
type RFC2136 struct {
	// Server is the host:port of the name server.
	Server string
	// KeyName and Secret, base64-encoded, make the HMAC-SHA256 key that
	// tsigoat signs with.
	KeyName string
	Secret  string
}

func (r RFC2136) entry() backendEntry {
	return backendEntry{Name: "relay", Type: "rfc2136", RFC2136: &rfc2136Entry{
		Server: r.Server,
		Key:    keyEntry{Name: r.KeyName, Algorithm: "hmac-sha256", Secret: r.Secret},
	}}
}

// The configuration file of tsigoat, as far as the scenarios use it.
type (
	keyEntry struct {
		Name      string `yaml:"name"`
		Algorithm string `yaml:"algorithm"`
		Secret    string `yaml:"secret"`
	}
	powerDNSEntry struct {
		URL     string `yaml:"url"`
		APIKey  string `yaml:"apiKey"`
		Timeout string `yaml:"timeout,omitempty"`
	}
	rfc2136Entry struct {
		Server string   `yaml:"server"`
		Key    keyEntry `yaml:"key"`
	}
	backendEntry struct {
		Name     string         `yaml:"name"`
		Type     string         `yaml:"type"`
		PowerDNS *powerDNSEntry `yaml:"powerdns,omitempty"`
		RFC2136  *rfc2136Entry  `yaml:"rfc2136,omitempty"`
	}
	ruleEntry struct {
		Key        string   `yaml:"key"`
		Names      []string `yaml:"names,omitempty"`
		Types      []string `yaml:"types,omitempty"`
		ACME       []string `yaml:"acme,omitempty"`
		MaxTTL     int      `yaml:"maxTTL,omitempty"`
		Content    string   `yaml:"content,omitempty"`
		MaxRecords int      `yaml:"maxRecords,omitempty"`
	}
	zoneEntry struct {
		Name                 string      `yaml:"name"`
		AllowUnauthenticated bool        `yaml:"allowUnauthenticated,omitempty"`
		Keys                 []string    `yaml:"keys,omitempty"`
		Policy               []ruleEntry `yaml:"policy,omitempty"`
	}
	configuration struct {
		Keys     []keyEntry     `yaml:"keys"`
		Backends []backendEntry `yaml:"backends"`
		Zones    []zoneEntry    `yaml:"zones"`
	}
)

// Config renders the configuration of tsigoat that serves the zones of the
// scenarios under parent, with every configured test key, on one backend. It
// is the only code that knows the configuration format.
func Config(scenarios []Scenario, parent string, b Backend) ([]byte, error) {
	config := configuration{Backends: []backendEntry{b.entry()}}
	var allKeys []string
	for _, k := range Keyring() {
		if !k.Configured {
			continue
		}
		config.Keys = append(config.Keys, keyEntry{Name: k.ConfigName, Algorithm: configAlgorithm(k.Algorithm), Secret: k.Secret()})
		allKeys = append(allKeys, k.ConfigName)
	}

	for i := range scenarios {
		s := &scenarios[i]
		name := s.ZoneName(parent)
		z := zoneEntry{Name: name, AllowUnauthenticated: s.Zone.Unauthenticated}
		for _, id := range s.Zone.Keys {
			z.Keys = append(z.Keys, configName(id))
		}
		for _, r := range s.Zone.Policy {
			compiled := ruleEntry{
				Key: configName(r.Key), Types: r.Types,
				MaxTTL: r.MaxTTL, Content: r.Content, MaxRecords: r.MaxRecords,
			}
			for _, pattern := range r.Names {
				compiled.Names = append(compiled.Names, absolute(pattern, name))
			}
			for _, certificate := range r.ACME {
				compiled.ACME = append(compiled.ACME, absolute(certificate, name))
			}
			z.Policy = append(z.Policy, compiled)
		}
		if !s.Zone.Unauthenticated && len(s.Zone.Keys) == 0 && len(s.Zone.Policy) == 0 {
			z.Keys = allKeys
		}
		config.Zones = append(config.Zones, z)
	}

	data, err := yaml.Marshal(&config)
	if err != nil {
		return nil, fmt.Errorf("rendering the configuration: %w", err)
	}
	return data, nil
}

// configName returns the configured name of a test key.
func configName(id string) string {
	k, _ := KeyByID(id)
	return k.ConfigName
}

// configAlgorithm turns a TSIG algorithm name into its configuration name:
// "hmac-sha256." becomes "hmac-sha256", and "hmac-md5.sig-alg.reg.int."
// becomes "hmac-md5".
func configAlgorithm(algorithm string) string {
	return strings.TrimSuffix(strings.TrimSuffix(algorithm, "."), ".sig-alg.reg.int")
}
