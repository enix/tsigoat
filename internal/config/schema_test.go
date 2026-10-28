package config

import "testing"

// TestSchema checks that the schema follows the types of the configuration
// file: closed objects, with the fields that their YAML names give.
func TestSchema(t *testing.T) {
	t.Parallel()
	s := Schema()
	if s["additionalProperties"] != false {
		t.Errorf("the configuration takes unknown fields: %v", s)
	}
	properties, _ := s["properties"].(map[string]any)
	for _, name := range []string{"listen", "admin", "keys", "backends", "zones"} {
		if _, ok := properties[name]; !ok {
			t.Errorf("the schema lacks %s", name)
		}
	}
	backend := properties["backends"].(map[string]any)["items"].(map[string]any)
	powerdns := backend["properties"].(map[string]any)["powerdns"].(map[string]any)
	if powerdns["additionalProperties"] != false {
		t.Errorf("a PowerDNS backend takes unknown fields: %v", powerdns)
	}
	if got := powerdns["properties"].(map[string]any)["apiKeyFile"]; got == nil {
		t.Errorf("a PowerDNS backend lacks apiKeyFile: %v", powerdns)
	}
	zone := properties["zones"].(map[string]any)["items"].(map[string]any)
	rule := zone["properties"].(map[string]any)["policy"].(map[string]any)["items"].(map[string]any)
	if got := rule["properties"].(map[string]any)["maxTTL"]; got.(map[string]any)["type"] != "integer" {
		t.Errorf("maxTTL of a rule: %v, want an integer", got)
	}
}
