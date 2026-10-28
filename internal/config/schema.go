package config

import (
	"fmt"
	"reflect"
	"strings"
)

// Schema returns the JSON schema of the configuration file, from the types
// that decode it: every object refuses the fields that tsigoat does not know,
// as its decoder does. The chart validates its config value with it, so that
// a misspelled or misshapen field fails the installation, rather than reach
// the ConfigMap, a secret with it, and fail the pod.
func Schema() map[string]any {
	return schemaOf(reflect.TypeFor[file]())
}

// jsonType is the keyword of the type of a value in a JSON schema.
const jsonType = "type"

// schemaOf returns the JSON schema of the YAML that decodes into a value of
// type t.
func schemaOf(t reflect.Type) map[string]any {
	switch t.Kind() {
	case reflect.Pointer:
		return schemaOf(t.Elem())
	case reflect.Struct:
		properties := map[string]any{}
		for field := range t.Fields() {
			name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			if name == "" || name == "-" {
				panic(fmt.Sprintf("field %s of %s has no YAML name", field.Name, t))
			}
			properties[name] = schemaOf(field.Type)
		}
		return map[string]any{jsonType: "object", "additionalProperties": false, "properties": properties}
	case reflect.Slice, reflect.Array:
		return map[string]any{jsonType: "array", "items": schemaOf(t.Elem())}
	case reflect.Map:
		if t.Key().Kind() == reflect.String {
			return map[string]any{jsonType: "object", "additionalProperties": schemaOf(t.Elem())}
		}
	case reflect.String:
		return map[string]any{jsonType: "string"}
	case reflect.Bool:
		return map[string]any{jsonType: "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return map[string]any{jsonType: "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{jsonType: "number"}
	case reflect.Invalid, reflect.Complex64, reflect.Complex128, reflect.Chan, reflect.Func,
		reflect.Interface, reflect.UnsafePointer:
	}
	panic(fmt.Sprintf("no JSON schema for %s", t))
}
