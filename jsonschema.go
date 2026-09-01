// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
)

// validateParamsSchema validates a claim's parameters against a capability's
// params_schema (JSON Schema subset). Supported keywords:
//
//	type / required / properties / additionalProperties / items / oneOf /
//	const / enum / minimum / maximum / minItems / maxItems / uniqueItems /
//	$defs / $ref ("#/$defs/...") / not
//
// This is intentionally a strict subset: it covers the structured capability
// specs (e.g. std/database-v1) without pulling in a full JSON Schema library.
func validateParamsSchema(raw json.RawMessage, params map[string]any) error {
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		return fmt.Errorf("parse params_schema: %w", err)
	}
	defs := schemaDefs(schema)
	if err := validateJSONSchema(schema, params, defs); err != nil {
		return err
	}
	return nil
}

func schemaDefs(schema map[string]any) map[string]any {
	if d, ok := schema["$defs"].(map[string]any); ok {
		return d
	}
	return nil
}

func resolveRef(ref string, defs map[string]any) (map[string]any, error) {
	// Only local "#/$defs/<name>" refs are supported.
	if !strings.HasPrefix(ref, "#/$defs/") {
		return nil, fmt.Errorf("unsupported $ref %q (only #/$defs/...)", ref)
	}
	name := strings.TrimPrefix(ref, "#/$defs/")
	if defs == nil {
		return nil, fmt.Errorf("$defs not present for $ref %q", ref)
	}
	target, ok := defs[name].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("$ref %q not found in $defs", ref)
	}
	return target, nil
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func checkType(t string, v any) error {
	switch t {
	case "object":
		if _, ok := v.(map[string]any); !ok {
			return fmt.Errorf("must be an object")
		}
	case "array":
		if _, ok := v.([]any); !ok {
			return fmt.Errorf("must be an array")
		}
	case "string":
		if _, ok := v.(string); !ok {
			return fmt.Errorf("must be a string")
		}
	case "integer":
		n, ok := asFloat(v)
		if !ok || math.Trunc(n) != n {
			return fmt.Errorf("must be an integer")
		}
	case "number":
		if _, ok := asFloat(v); !ok {
			return fmt.Errorf("must be a number")
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("must be a boolean")
		}
	default:
		return fmt.Errorf("unsupported schema type %q", t)
	}
	return nil
}

// validateJSONSchema validates value against schema. defs carries the
// params_schema root $defs for $ref resolution.
func validateJSONSchema(schema map[string]any, value any, defs map[string]any) error {
	// $ref takes precedence.
	if ref, ok := schema["$ref"].(string); ok {
		target, err := resolveRef(ref, defs)
		if err != nil {
			return err
		}
		return validateJSONSchema(target, value, defs)
	}

	// const
	if c, ok := schema["const"]; ok {
		if !reflect.DeepEqual(c, value) {
			return fmt.Errorf("must equal %v", c)
		}
	}

	// enum
	if e, ok := schema["enum"].([]any); ok {
		matched := false
		for _, cand := range e {
			if reflect.DeepEqual(cand, value) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("must be one of %v", e)
		}
	}

	// type
	if t, ok := schema["type"].(string); ok {
		if err := checkType(t, value); err != nil {
			return err
		}
	}

	// numeric bounds
	if n, ok := asFloat(value); ok {
		if mn, ok := schema["minimum"].(float64); ok && n < mn {
			return fmt.Errorf("must be >= %v", mn)
		}
		if mx, ok := schema["maximum"].(float64); ok && n > mx {
			return fmt.Errorf("must be <= %v", mx)
		}
	}

	// object keywords
	if obj, ok := value.(map[string]any); ok {
		props, _ := schema["properties"].(map[string]any)

		// required
		if req, ok := schema["required"].([]any); ok {
			for _, r := range req {
				name, _ := r.(string)
				if _, ok := obj[name]; !ok {
					return fmt.Errorf("missing required property %q", name)
				}
			}
		}

		// properties
		for name, ps := range props {
			if pv, ok := obj[name]; ok {
				sub, ok := ps.(map[string]any)
				if !ok {
					continue
				}
				if err := validateJSONSchema(sub, pv, defs); err != nil {
					return fmt.Errorf("property %q: %w", name, err)
				}
			}
		}

		// additionalProperties
		if ap, ok := schema["additionalProperties"]; ok {
			switch apv := ap.(type) {
			case bool:
				if apv {
					break
				}
				for k := range obj {
					if _, defined := props[k]; !defined {
						return fmt.Errorf("additional property %q not allowed", k)
					}
				}
			case map[string]any:
				for k, v := range obj {
					if _, defined := props[k]; !defined {
						if err := validateJSONSchema(apv, v, defs); err != nil {
							return fmt.Errorf("property %q: %w", k, err)
						}
					}
				}
			}
		}
	}

	// array keywords
	if arr, ok := value.([]any); ok {
		if items, ok := schema["items"].(map[string]any); ok {
			for i, it := range arr {
				if err := validateJSONSchema(items, it, defs); err != nil {
					return fmt.Errorf("item %d: %w", i, err)
				}
			}
		}
		if mn, ok := schema["minItems"].(float64); ok && float64(len(arr)) < mn {
			return fmt.Errorf("must have at least %v items", mn)
		}
		if mx, ok := schema["maxItems"].(float64); ok && float64(len(arr)) > mx {
			return fmt.Errorf("must have at most %v items", mx)
		}
		if uniq, ok := schema["uniqueItems"].(bool); ok && uniq {
			for i := 0; i < len(arr); i++ {
				for j := i + 1; j < len(arr); j++ {
					if reflect.DeepEqual(arr[i], arr[j]) {
						return fmt.Errorf("items must be unique (duplicate at %d)", j)
					}
				}
			}
		}
	}

	// oneOf
	if oneOf, ok := schema["oneOf"].([]any); ok {
		var lastErr error
		matched := false
		for _, o := range oneOf {
			sub, ok := o.(map[string]any)
			if !ok {
				continue
			}
			if err := validateJSONSchema(sub, value, defs); err == nil {
				matched = true
				break
			} else {
				lastErr = err
			}
		}
		if !matched {
			return fmt.Errorf("must match one of the schemas: %v", lastErr)
		}
	}

	// not
	if n, ok := schema["not"].(map[string]any); ok {
		if err := validateJSONSchema(n, value, defs); err == nil {
			return fmt.Errorf("must NOT match the schema")
		}
	}

	return nil
}
