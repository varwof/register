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
	if scheme != "std/database-v1" {
		return nil
	}
	switch capability {
	case "query:SELECT", "query:UPDATE", "query:DELETE":
		return validateDatabaseTableParams(capability, raw)
	default:
		return nil
	}
}

// validateDatabaseTableParams implements the database-v1 contract for the
// four table-scoped capabilities that share the tables / columns / row_filter
// shape (query:SELECT / query:UPDATE / query:DELETE).  The predicate-allowlist
// semantics mirror the gateway's Scoped.filterable: a declared filter_columns
// list binds first (even when the returnable list is "*"), then the returnable
// column set, and a "*" or unlisted columns entry means unrestricted.
func validateDatabaseTableParams(capability string, raw json.RawMessage) error {
	var p struct {
		Tables        []string            `json:"tables"`
		Columns       map[string]any      `json:"columns"`
		FilterColumns map[string][]string `json:"filter_columns"`
		RowFilter     map[string]any      `json:"row_filter"`
		Limit         *struct {
			Max int `json:"max"`
		} `json:"limit"`
		Aggregate *bool     `json:"aggregate"`
		OrderBy   *[]string `json:"order_by"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("malformed params: %w", err)
	}
	if len(p.Tables) == 0 || len(p.Tables) > 32 {
		return fmt.Errorf("tables must contain 1..32 entries")
	}
	// nil == no column restriction.  This is exactly a "*" entry, and also the
	// meaning of a table the grant names in `tables` but not in `columns`
	// (the gateway's ColumnMap.isStar returns true for both).
	allowed := make(map[string]map[string]bool, len(p.Tables))
	for _, t := range p.Tables {
		allowed[t] = nil
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
		case []any:
			set := make(map[string]bool, len(cv))
			for _, c := range cv {
				cs, ok := c.(string)
				if !ok {
					return fmt.Errorf("columns[%q] must be strings", tbl)
				}
				set[cs] = true
			}
			if len(set) == 0 {
				return fmt.Errorf("columns[%q] must not be empty", tbl)
			}
			allowed[tbl] = set
		default:
			return fmt.Errorf("columns[%q] must be an array or \"*\"", tbl)
		}
	}
	// filter-only columns: usable in WHERE but never returned.
	filterAllowed := make(map[string]map[string]bool, len(p.Tables))
	for tbl, cols := range p.FilterColumns {
		if _, ok := allowed[tbl]; !ok {
			return fmt.Errorf("filter_columns references unlisted table %q", tbl)
		}
		if len(cols) == 0 {
			return fmt.Errorf("filter_columns[%q] must not be empty", tbl)
		}
		set := make(map[string]bool, len(cols))
		for _, c := range cols {
			set[c] = true
		}
		filterAllowed[tbl] = set
	}
	if p.RowFilter != nil {
		for tbl, filt := range p.RowFilter {
			if _, ok := allowed[tbl]; !ok {
				return fmt.Errorf("row_filter references unlisted table %q", tbl)
			}
			permit := filterAllowed[tbl]
			if len(permit) == 0 {
				permit = allowed[tbl]
			}
			if err := checkFilterColumns(filt, permit, tbl); err != nil {
				return err
			}
		}
	} else if capability == "query:UPDATE" || capability == "query:DELETE" {
		return fmt.Errorf("row_filter is required by %s", capability)
	}
	if p.Limit != nil && (p.Limit.Max < 1 || p.Limit.Max > 100000) {
		return fmt.Errorf("limit.max must be in 1..100000")
	}
	if p.OrderBy != nil {
		if capability == "query:SELECT" {
			return fmt.Errorf("order_by is only declared by query:UPDATE and query:DELETE")
		}
		if len(*p.OrderBy) == 0 {
			return fmt.Errorf("order_by must name at least one column")
		}
		seen := make(map[string]bool, len(*p.OrderBy))
		for _, c := range *p.OrderBy {
			if c == "" {
				return fmt.Errorf("order_by entries must be non-empty column names")
			}
			if seen[c] {
				return fmt.Errorf("order_by entries must be unique (repeat %q)", c)
			}
			seen[c] = true
		}
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
