package scenario

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

// PowerDNS locates the PowerDNS API that tsigoat writes to.
type PowerDNS struct {
	URL    string
	APIKey string
	// Timeout of the calls to the API, such as "1s"; the default when empty.
	Timeout string
}

// Config renders the configuration of tsigoat that serves the zones of the
// scenarios under parent, with every configured test key. It is the only
// code that knows the configuration format.
func Config(scenarios []Scenario, parent string, pdns PowerDNS) ([]byte, error) {
	type key struct {
		Name      string `yaml:"name"`
		Algorithm string `yaml:"algorithm"`
		Secret    string `yaml:"secret"`
	}
	type powerDNS struct {
		URL     string `yaml:"url"`
		APIKey  string `yaml:"apiKey"`
		Timeout string `yaml:"timeout,omitempty"`
	}
	type backend struct {
		Name     string   `yaml:"name"`
		Type     string   `yaml:"type"`
		PowerDNS powerDNS `yaml:"powerdns"`
	}
	type rule struct {
		Key   string   `yaml:"key"`
		Names []string `yaml:"names"`
		Types []string `yaml:"types,omitempty"`
	}
	type zone struct {
		Name                 string   `yaml:"name"`
		AllowUnauthenticated bool     `yaml:"allowUnauthenticated,omitempty"`
		Keys                 []string `yaml:"keys,omitempty"`
		Policy               []rule   `yaml:"policy,omitempty"`
	}
	type configuration struct {
		Keys     []key     `yaml:"keys"`
		Backends []backend `yaml:"backends"`
		Zones    []zone    `yaml:"zones"`
	}

	config := configuration{
		Backends: []backend{{Name: "pdns", Type: "powerdns", PowerDNS: powerDNS(pdns)}},
	}
	var allKeys []string
	for _, k := range Keyring() {
		if !k.Configured {
			continue
		}
		config.Keys = append(config.Keys, key{Name: k.ConfigName, Algorithm: configAlgorithm(k.Algorithm), Secret: k.Secret()})
		allKeys = append(allKeys, k.ConfigName)
	}

	for i := range scenarios {
		s := &scenarios[i]
		name := s.ZoneName(parent)
		z := zone{Name: name, AllowUnauthenticated: s.Zone.Unauthenticated}
		for _, id := range s.Zone.Keys {
			z.Keys = append(z.Keys, configName(id))
		}
		for _, r := range s.Zone.Policy {
			compiled := rule{Key: configName(r.Key), Types: r.Types}
			for _, pattern := range r.Names {
				compiled.Names = append(compiled.Names, absolute(pattern, name))
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
