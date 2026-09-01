// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"encoding/json"
	"fmt"
)

// validateFlatParamValue validates a single claimed parameter value against
// its flat ParameterDef (type/min/max/enum/required). Previously the flat
// path only checked that the key existed, so values like
// `max_validity_days: -1` or `ca_scope: 123` passed validation (P0-1).
func validateFlatParamValue(pd ParameterDef, key string, value any) error {
	// Value type + bounds.
	switch pd.Type {
	case "int":
		n, ok := asJSONNumber(value)
		if !ok {
			return fmt.Errorf("parameter %q: must be an integer, got %T", key, value)
		}
		if mn, ok := asFloat(pd.Min); ok && n < mn {
			return fmt.Errorf("parameter %q: %v is below minimum %v", key, n, mn)
		}
		if mx, ok := asFloat(pd.Max); ok && n > mx {
			return fmt.Errorf("parameter %q: %v exceeds maximum %v", key, n, mx)
		}
	case "bool":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("parameter %q: must be a boolean, got %T", key, value)
		}
	case "string":
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("parameter %q: must be a string, got %T", key, value)
		}
		if len(pd.Enum) > 0 && !containsString(pd.Enum, s) {
			return fmt.Errorf("parameter %q: %q not in allowed values %v", key, s, pd.Enum)
		}
	case "list":
		arr, ok := value.([]any)
		if !ok {
			return fmt.Errorf("parameter %q: must be a list, got %T", key, value)
		}
		for _, e := range arr {
			s, ok := e.(string)
			if !ok {
				return fmt.Errorf("parameter %q: list element must be a string, got %T", key, e)
			}
			if len(pd.Enum) > 0 && !containsString(pd.Enum, s) {
				return fmt.Errorf("parameter %q: %q not in allowed values %v", key, s, pd.Enum)
			}
		}
	case "":
		// No declared type: anything goes (legacy compatibility).
		return nil
	default:
		return fmt.Errorf("parameter %q: unsupported ParameterDef type %q", key, pd.Type)
	}
	return nil
}

// validateFlatParamRequired checks the capability's declared-required
// parameters are present in the claim (narrowing may not drop a required
// parameter).
func validateFlatParamRequired(entry *CapabilityEntry, params map[string]any) error {
	for k, pd := range entry.Parameters {
		if pd.Required {
			if _, ok := params[k]; !ok {
				return fmt.Errorf("missing required parameter %q for %s", k, entry.ID)
			}
		}
	}
	return nil
}

func asJSONNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func containsString(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
