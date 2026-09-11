// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/varwof/register"
	"github.com/varwof/register/ruleexec"
)

const schemesDir = "../../testdata/capability"

func testRegistry(t *testing.T) *register.Registry {
	t.Helper()
	reg, err := register.NewRegistryFromDisk(schemesDir)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

func validClaim() claim {
	return claim{
		SchemeID:   "std/database-v1",
		Capability: "query:SELECT",
		Parameters: map[string]any{
			"tables":  []any{"customers"},
			"columns": map[string]any{"customers": []any{"id", "name"}},
		},
	}
}

func TestBuildPlanGeneratesRule(t *testing.T) {
	plan, err := buildPlan([]claim{validClaim()}, testRegistry(t), nil, 1, 0, "rules")
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	if len(plan) != 1 {
		t.Fatalf("plan = %d entries, want 1", len(plan))
	}
	p := plan[0]
	if want := filepath.Join("rules", "std/database-v1", "v1.0.json"); p.path != want {
		t.Errorf("path = %q, want %q", p.path, want)
	}
	if p.rule.Capability != "query:SELECT" || p.rule.Scheme != "std/database-v1" {
		t.Errorf("unexpected rule: %+v", p.rule)
	}
	if !strings.Contains(string(p.rule.Params), "customers") {
		t.Errorf("parameters not carried over: %s", p.rule.Params)
	}
}

// The whole point of the gate: a claim that does not satisfy the scheme's
// params_schema must not produce a rule (the operator would otherwise sign a
// rule the registry never authorised).
func TestBuildPlanRejectsParamsOutsideSchemeContract(t *testing.T) {
	c := validClaim()
	delete(c.Parameters, "columns") // required by std/database-v1 query:SELECT
	if _, err := buildPlan([]claim{c}, testRegistry(t), nil, 1, 0, "rules"); err == nil {
		t.Fatal("missing required parameter must be rejected, not silently accepted")
	}
}

func TestBuildPlanRejectsUnknownCapability(t *testing.T) {
	c := validClaim()
	c.Capability = "query:NOPE"
	if _, err := buildPlan([]claim{c}, testRegistry(t), nil, 1, 0, "rules"); err == nil {
		t.Fatal("unknown capability must be rejected")
	}
}

func TestBuildPlanRejectsUnknownScheme(t *testing.T) {
	c := validClaim()
	c.SchemeID = "nobody/nothing"
	if _, err := buildPlan([]claim{c}, testRegistry(t), nil, 1, 0, "rules"); err == nil {
		t.Fatal("unknown scheme must be rejected")
	}
}

func TestBuildPlanAscendingMinorPerScheme(t *testing.T) {
	a, b := validClaim(), validClaim()
	plan, err := buildPlan([]claim{a, b}, testRegistry(t), nil, 1, 3, "rules")
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	if len(plan) != 2 {
		t.Fatalf("plan = %d entries, want 2", len(plan))
	}
	if got := filepath.Base(plan[0].path); got != "v1.3.json" {
		t.Errorf("first = %s, want v1.3.json", got)
	}
	if got := filepath.Base(plan[1].path); got != "v1.4.json" {
		t.Errorf("second = %s, want v1.4.json", got)
	}
	if plan[0].rule.RuleID == plan[1].rule.RuleID {
		t.Error("rule ids must be unique per version")
	}
}

// A template supplies the runtime half (conditions / constraints / flow) so the
// generated rule is not just a parameter copy.
func TestBuildPlanCarriesTemplate(t *testing.T) {
	tpl, err := ruleexec.LoadRuleBytes([]byte(`{
	  "rule_id": "t", "version": "1.0.0", "scheme": "std/database-v1",
	  "capability": "query:SELECT", "params": {"tables": ["customers"], "columns": {"customers": ["id"]}},
	  "conditions": {"op": "eq", "path": "request.tenant_id", "value": "org-a"},
	  "constraints": [{"scheme": "varwof/constraint-v1", "id": "allowed-cidr"}],
	  "flow": {"steps": [{"name": "q", "kind": "op", "op": "db:select"}]}
	}`))
	if err != nil {
		t.Fatalf("template: %v", err)
	}
	plan, err := buildPlan([]claim{validClaim()}, testRegistry(t), tpl, 1, 0, "rules")
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	got := plan[0].rule
	if got.Conditions == nil || got.Conditions.Op != "eq" {
		t.Errorf("conditions not carried from template: %+v", got.Conditions)
	}
	if len(got.Constraints) != 1 {
		t.Errorf("constraints not carried from template: %+v", got.Constraints)
	}
	if got.Flow == nil || len(got.Flow.Steps) != 1 {
		t.Errorf("flow not carried from template: %+v", got.Flow)
	}
}

// Fail-closed: nothing is planned when any claim fails, so the caller cannot
// write a partial rule set.
func TestBuildPlanIsAllOrNothing(t *testing.T) {
	bad := validClaim()
	bad.Capability = "query:NOPE"
	plan, err := buildPlan([]claim{validClaim(), bad}, testRegistry(t), nil, 1, 0, "rules")
	if err == nil {
		t.Fatal("expected error for the bad claim")
	}
	if len(plan) != 0 {
		t.Fatalf("plan = %d entries on failure, want 0", len(plan))
	}
}
