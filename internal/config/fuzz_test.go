package config_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/enix/tsigoat/internal/config"
)

// FuzzParse feeds arbitrary documents to the parser: it must never panic,
// and a configuration it accepts must hold together.
func FuzzParse(f *testing.F) {
	paths, err := filepath.Glob("../../test/config/*/*.yaml")
	if err != nil {
		f.Fatal(err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}

	options := testOptions()
	options.ReadFile = func(string) ([]byte, error) {
		return []byte("dGhpcyBpcyBhIHRlc3Qgc2VjcmV0LCB0aGlydHktdHdvIQ=="), nil // gitleaks:allow (fixture)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, _, err := config.Parse(data, options)
		if err != nil {
			return
		}
		if len(c.Listen) == 0 || len(c.Zones) == 0 {
			t.Fatalf("accepted a configuration without listen addresses or zones: %+v", c)
		}
		backends := map[string]bool{}
		for _, b := range c.Backends {
			backends[b.Name] = true
		}
		keys := map[string]bool{}
		for _, k := range c.Keys {
			if len(k.Secret) == 0 {
				t.Fatalf("accepted key %q without a secret", k.Name)
			}
			keys[k.Name] = true
		}
		for _, z := range c.Zones {
			if !backends[z.Backend] {
				t.Fatalf("zone %q uses unknown backend %q", z.Name, z.Backend)
			}
			for _, name := range z.Keys {
				if !keys[name] {
					t.Fatalf("zone %q lists unknown key %q", z.Name, name)
				}
			}
			for _, rule := range z.Policy {
				if !keys[rule.Key] || slices.Contains(z.Keys, rule.Key) {
					t.Fatalf("zone %q has a rule for key %q, unknown or already listed", z.Name, rule.Key)
				}
			}
		}
	})
}
