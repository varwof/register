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
	v := &schemaValidator{defs: defs}
	if err := v.validate(schema, params); err != nil {
		return err
	}
	return nil
}

// maxSchemaRefDepth bounds $ref following and schema recursion.  A cyclic
// $ref (e.g. a $def that only references itself) would otherwise recurse
// forever and blow the stack (audit 2026-09-16, R8).  Legitimate recursive
// schemas (e.g. the row_filter "and"/"or"/"not" grammar) nest by consuming
// the value, so depth 100 is ample for real rules while capping runaway
// $ref-only cycles.
const maxSchemaRefDepth = 100

// schemaValidator carries per-validation state: the $defs table plus the
// recursion depth guarding against cyclic $ref graphs.
type schemaValidator struct {
	defs  map[string]any
	depth int
}

func (v *schemaValidator) child() *schemaValidator {
	cp := *v
	cp.depth++
	return &cp
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

// validate validates value against schema. defs carries the params_schema
// root $defs for $ref resolution.  Depth is bounded, which stops runaway
// ($ref-only) cycles from overflowing the stack (audit 2026-09-16, R8).
func (v *schemaValidator) validate(schema map[string]any, value any) error {
	// $ref takes precedence.
	if ref, ok := schema["$ref"].(string); ok {
		target, err := resolveRef(ref, v.defs)
		if err != nil {
			return err
		}
		if v.depth >= maxSchemaRefDepth {
			return fmt.Errorf("$ref nesting exceeds %d", maxSchemaRefDepth)
		}
		return v.child().validate(target, value)
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
				if err := v.child().validate(sub, pv); err != nil {
					return fmt.Errorf("property %q: %w", name, err)
				}
			}
		}

		// additionalProperties — FAIL-CLOSED BY DEFAULT.
		//
		// A schema that declares `properties` but omits `additionalProperties`
		// is treated as closed: an undeclared key is rejected.  JSON Schema
		// itself defaults to permissive, but these schemas are a security
		// contract for capability parameters, and a permissive default meant a
		// typo ("tabel" for "tables") was accepted on the schema path while the
		// flat-parameters path rejected it — two answers for one contract.  A
		// capability that genuinely wants extra keys says so explicitly with
		// `"additionalProperties": true` or a sub-schema.
		ap, hasAP := schema["additionalProperties"]
		if !hasAP {
			// Only a schema that actually declares an object shape
			// (`properties`) is closed.  A schema whose object constraint
			// lives in oneOf/allOf branches (e.g. the recursive filter
			// grammar) has no top-level properties and stays permissive here;
			// its branches are validated on their own.
			if len(props) > 0 {
				for k := range obj {
					if _, defined := props[k]; !defined {
						return fmt.Errorf("additional property %q not allowed (declare it in params_schema, or set additionalProperties)", k)
					}
				}
			}
		} else {
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
				for k, val := range obj {
					if _, defined := props[k]; !defined {
						if err := v.child().validate(apv, val); err != nil {
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
				if err := v.child().validate(items, it); err != nil {
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
			if err := v.child().validate(sub, value); err == nil {
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
		if err := v.child().validate(n, value); err == nil {
			return fmt.Errorf("must NOT match the schema")
		}
	}

	return nil
}
