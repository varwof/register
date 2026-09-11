// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/varwof/register"
	"github.com/varwof/register/semantics"
)

// Rule is the signed rule file format (draft, see
// docs/database-scheme-design.md §8).
type Rule struct {
	RuleID      string          `json:"rule_id"`
	Version     string          `json:"version"`
	Scheme      string          `json:"scheme"`
	Capability  string          `json:"capability"`
	Params      json.RawMessage `json:"params"`
	Conditions  *Condition      `json:"conditions,omitempty"`
	Constraints []Constraint    `json:"constraints,omitempty"`
	Flow        *Flow           `json:"flow,omitempty"`
}

// Constraint references a registered constraint type.
type Constraint struct {
	Scheme string          `json:"scheme"`
	ID     string          `json:"id"`
	Params json.RawMessage `json:"params,omitempty"`
}

// LoadRule reads a rule file.
func LoadRule(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadRuleBytes(data)
}

// LoadRuleBytes parses a rule from JSON bytes.
//
// Unknown fields are rejected (fail-closed): a misspelled key such as
// "condtions" would otherwise be dropped silently and the rule would load — and
// execute — without the constraint the author meant to write.  Rules are
// machine-generated as often as hand-written, so the loader must not be lenient
// about field names.
func LoadRuleBytes(data []byte) (*Rule, error) {
	var r Rule
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parse rule: %w", err)
	}
	if r.RuleID == "" || r.Version == "" || r.Scheme == "" || r.Capability == "" {
		return nil, fmt.Errorf("rule requires rule_id, version, scheme, capability")
	}
	if err := ValidateStructure(&r); err != nil {
		return nil, fmt.Errorf("rule structure: %w", err)
	}
	return &r, nil
}

// Validate checks the rule against the scheme registry and validates the
// rule parameters with the capability semantics (CLC-v1), not with
// ruleexec-local rules -- see docs/capability-language-layers.md.
func (r *Rule) Validate(reg *register.Registry) error {
	if _, _, err := reg.ValidateCapability(r.Scheme + ":" + r.Capability); err != nil {
		return fmt.Errorf("capability %s:%s: %w", r.Scheme, r.Capability, err)
	}
	for _, c := range r.Constraints {
		if c.Scheme != "varwof/constraint-v1" && c.Scheme != "constraint" && c.Scheme != "constraint-v1" {
			return fmt.Errorf("constraint scheme %q not allowed", c.Scheme)
		}
	}
	var params map[string]any
	if len(r.Params) > 0 {
		if err := json.Unmarshal(r.Params, &params); err != nil {
			return fmt.Errorf("params: must be a JSON object: %w", err)
		}
		if err := semantics.ValidateGrantParams(params); err != nil {
			return fmt.Errorf("params: %w", err)
		}
	}
	// The capability's parameter contract, from the registry: a declared
	// params_schema is enforced data-driven (including its `required` list),
	// falling back to the flat contract.  Without this the rule path was
	// laxer than the claims path — a rule could omit a required parameter
	// (e.g. `columns` for std/database-v1:query:SELECT) and still be signed.
	if err := reg.ValidateParams(r.Scheme, r.Capability, params); err != nil {
		return fmt.Errorf("params: %w", err)
	}
	// Scheme-specific structural contract (owned by the scheme, not by ruleexec).
	if err := register.ValidateSchemeParams(r.Scheme, r.Capability, r.Params); err != nil {
		return fmt.Errorf("params: %w", err)
	}
	return nil
}

// checkFilterColumns ensures a row filter only references allowed
// columns.
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
