// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"strings"
	"testing"
)

// The rule path and the claims path must enforce the SAME parameter contract.
// They are two paths over one contract (registry.ValidateParams), not two
// implementations of it: before 2026-09-11 the rule path used a hard-coded
// validator that (a) skipped the schema's `required` list and (b) returned nil
// for every scheme but std/database-v1, so a signed rule could declare
// parameters the registry never authorised.
func TestRuleEnforcesRegistryParameterContract(t *testing.T) {
	reg := demoRegistry()

	withColumns := `{
	  "rule_id": "r", "version": "1.0.0", "scheme": "std/database-v1",
	  "capability": "query:SELECT",
	  "params": {"tables": ["customers"], "columns": {"customers": ["id"]}}
	}`
	rule, err := LoadRuleBytes([]byte(withColumns))
	if err != nil {
		t.Fatalf("rule with the required parameters must load: %v", err)
	}
	if err := rule.Validate(reg); err != nil {
		t.Fatalf("rule with the required parameters must validate: %v", err)
	}

	// (a) `columns` is required by the scheme's params_schema.
	missingRequired := `{
	  "rule_id": "r", "version": "1.0.0", "scheme": "std/database-v1",
	  "capability": "query:SELECT",
	  "params": {"tables": ["customers"]}
	}`
	rule, err = LoadRuleBytes([]byte(missingRequired))
	if err != nil {
		t.Fatalf("structure alone should still parse: %v", err)
	}
	err = rule.Validate(reg)
	if err == nil {
		t.Fatal("omitting the schema's required parameter must be rejected on the rule path")
	}
	if !strings.Contains(err.Error(), "columns") {
		t.Errorf("error should name the missing parameter, got: %v", err)
	}

	// (b) unknown parameters stay rejected.
	unknown := `{
	  "rule_id": "r", "version": "1.0.0", "scheme": "std/database-v1",
	  "capability": "query:SELECT",
	  "params": {"tables": ["customers"], "columns": {"customers": ["id"]}, "nonsense": 1}
	}`
	rule, err = LoadRuleBytes([]byte(unknown))
	if err != nil {
		t.Fatalf("structure alone should still parse: %v", err)
	}
	if err := rule.Validate(reg); err == nil {
		t.Fatal("an unknown parameter must be rejected on the rule path")
	}
}
