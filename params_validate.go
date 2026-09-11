// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"encoding/json"
	"fmt"
)

// ValidateSchemeParams validates a capability's parameters against the
// CONTRACT OF THE SCHEME that defines them.  Scheme-specific structural rules
// live here, with the scheme, and are NOT re-implemented by consumers such as
// the rule execution engine (see ruleexec and docs/capability-language-layers.md).
//
// Generic capability semantics (nulls, explicit empty bounds, subset rules)
// are defined once by CLC-v1 and validated via
// github.com/varwof/register/semantics.
func ValidateSchemeParams(scheme, capability string, raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	switch {
	case scheme == "std/database-v1" && capability == "query:SELECT":
		return validateDatabaseSelectParams(raw)
	default:
		return nil
	}
}

// validateDatabaseSelectParams implements the database-v1 SELECT contract:
// tables / columns / row_filter / limit.
func validateDatabaseSelectParams(raw json.RawMessage) error {
	var p struct {
		Tables        []string            `json:"tables"`
		Columns       map[string]any      `json:"columns"`
		FilterColumns map[string][]string `json:"filter_columns,omitempty"`
		RowFilter     map[string]any      `json:"row_filter"`
		Limit         *struct {
			Max int `json:"max"`
		} `json:"limit"`
		Aggregate *bool `json:"aggregate"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("malformed params: %w", err)
	}
	if len(p.Tables) == 0 || len(p.Tables) > 32 {
		return fmt.Errorf("tables must contain 1..32 entries")
	}
	allowed := make(map[string]map[string]bool, len(p.Tables))
	for _, t := range p.Tables {
		allowed[t] = map[string]bool{}
	}
	for tbl, v := range p.Columns {
		if _, ok := allowed[tbl]; !ok {
			return fmt.Errorf("columns references unlisted table %q", tbl)
		}
		switch cv := v.(type) {
		case string:
			if cv != "*" {
				return fmt.Errorf("columns[%q] must be an array or \"*\"", tbl)
			}
			allowed[tbl] = nil // nil == star
		case []any:
			if len(cv) == 0 {
				return fmt.Errorf("columns[%q] must not be empty", tbl)
			}
			for _, c := range cv {
				cs, ok := c.(string)
				if !ok {
					return fmt.Errorf("columns[%q] must be strings", tbl)
				}
				allowed[tbl][cs] = true
			}
		default:
			return fmt.Errorf("columns[%q] must be an array or \"*\"", tbl)
		}
	}
	// filter-only columns: usable in WHERE but never returned.
	filterAllowed := make(map[string]map[string]bool, len(p.Tables))
	for _, t := range p.Tables {
		filterAllowed[t] = map[string]bool{}
	}
	for tbl, cols := range p.FilterColumns {
		if _, ok := allowed[tbl]; !ok {
			return fmt.Errorf("filter_columns references unlisted table %q", tbl)
		}
		if len(cols) == 0 {
			return fmt.Errorf("filter_columns[%q] must not be empty", tbl)
		}
		for _, c := range cols {
			filterAllowed[tbl][c] = true
		}
	}
	if p.RowFilter != nil {
		for tbl, filt := range p.RowFilter {
			if _, ok := allowed[tbl]; !ok {
				return fmt.Errorf("row_filter references unlisted table %q", tbl)
			}
			// a filter column must be either an allowed (returnable)
			// column or a declared filter-only column
			permit := filterAllowed[tbl]
			if allowed[tbl] == nil { // "*" allows everything
				permit = nil
			}
			if err := checkFilterColumns(filt, permit, tbl); err != nil {
				return err
			}
		}
	}
	if p.Limit != nil && (p.Limit.Max < 1 || p.Limit.Max > 100000) {
		return fmt.Errorf("limit.max must be in 1..100000")
	}
	return nil
}

func checkFilterColumns(node any, allowed map[string]bool, tbl string) error {
	m, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("row_filter[%q] must be a filter object", tbl)
	}
	if col, ok := m["column"].(string); ok {
		if allowed != nil && !allowed[col] {
			return fmt.Errorf("row_filter[%q] references column %q outside the column allowlist", tbl, col)
		}
		return nil
	}
	if list, ok := m["and"].([]any); ok {
		for _, it := range list {
			if err := checkFilterColumns(it, allowed, tbl); err != nil {
				return err
			}
		}
		return nil
	}
	if list, ok := m["or"].([]any); ok {
		for _, it := range list {
			if err := checkFilterColumns(it, allowed, tbl); err != nil {
				return err
			}
		}
		return nil
	}
	if inner, ok := m["not"]; ok {
		return checkFilterColumns(inner, allowed, tbl)
	}
	return fmt.Errorf("row_filter[%q] invalid filter structure", tbl)
}
