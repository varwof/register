// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/varwof/register"
	pki "github.com/varwof/types"
)

func noopHandler(op string, vars, req map[string]any) (map[string]any, error) {
	return nil, nil
}

func ctxWith(vars map[string]any, req map[string]any) *FlowContext {
	if vars == nil {
		vars = map[string]any{}
	}
	if req == nil {
		req = map[string]any{}
	}
	return &FlowContext{Vars: vars, Request: req, Handler: noopHandler}
}

func wantBudgetKind(t *testing.T, err error, kind BudgetKind) {
	t.Helper()
	var be *BudgetError
	if !errors.As(err, &be) {
		t.Fatalf("expected BudgetError, got: %v", err)
	}
	if be.Kind != kind {
		t.Fatalf("expected budget kind %v, got %v (%v)", kind, be.Kind, err)
	}
}

// --- DoS: static pre-check -------------------------------------------

// --- DoS: runtime budgets ---------------------------------------------

func TestAllowedNesting(t *testing.T) {
	// if nesting seq (allowed)
	wif := Flow{Steps: []Step{{Kind: "if", Condition: &Condition{Op: "eq", Path: "flag", Value: false},
		Then: []Step{{Kind: "seq", Steps: []Step{{Kind: "op", Op: "noop"}}}}}}}
	if err := CheckStaticBounds(wif, NewBudget()); err != nil {
		t.Fatalf("if->seq should be allowed: %v", err)
	}
}

func TestBudgetStepsStopped(t *testing.T) {
	steps := make([]Step, 200_000)
	for i := range steps {
		steps[i] = Step{Kind: "op", Op: "noop"}
	}
	b := NewBudget()
	err := RunFlow(Flow{Steps: steps}, ctxWith(nil, nil), b)
	wantBudgetKind(t, err, KindSteps)
}

// --- condition evaluator ----------------------------------------------

func TestConditionEval(t *testing.T) {
	req := map[string]any{
		"tenant_id": "org-a",
		"time":      "2026-08-23T10:00:00Z",
		"params":    map[string]any{"amount": float64(500)},
	}
	ctx := map[string]any{"request": req}

	cases := []struct {
		name string
		cond Condition
		want bool
	}{
		{"eq true", Condition{Op: "eq", Path: "request.tenant_id", Value: "org-a"}, true},
		{"eq false", Condition{Op: "eq", Path: "request.tenant_id", Value: "org-b"}, false},
		{"and all true", Condition{Op: "and", Items: []Condition{
			{Op: "eq", Path: "request.tenant_id", Value: "org-a"},
			{Op: "lte", Path: "request.params.amount", Value: float64(1000)},
		}}, true},
		{"and one false", Condition{Op: "and", Items: []Condition{
			{Op: "eq", Path: "request.tenant_id", Value: "org-a"},
			{Op: "gt", Path: "request.params.amount", Value: float64(1000)},
		}}, false},
		{"or", Condition{Op: "or", Items: []Condition{
			{Op: "eq", Path: "request.tenant_id", Value: "org-b"},
			{Op: "eq", Path: "request.tenant_id", Value: "org-a"},
		}}, true},
		{"not", Condition{Op: "not", Items: []Condition{{Op: "eq", Path: "request.tenant_id", Value: "org-b"}}}, true},
		{"between", Condition{Op: "between", Path: "request.params.amount", Window: []string{"1", "1000"}}, true},
		{"in", Condition{Op: "in", Path: "request.tenant_id", Value: []any{"org-a", "org-b"}}, true},
		{"is-null missing", Condition{Op: "is-null", Path: "request.missing"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := EvalCondition(c.cond, ctx, NewBudget(), 0)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestConditionEvalErrors(t *testing.T) {
	ctx := map[string]any{"request": map[string]any{}}
	if _, err := EvalCondition(Condition{Op: "bogus"}, ctx, NewBudget(), 0); err == nil {
		t.Fatalf("unknown op must fail")
	}
	if _, err := EvalCondition(Condition{Op: "eq", Path: "request.missing", Value: 1}, ctx, NewBudget(), 0); err == nil {
		t.Fatalf("missing path must fail")
	}
}

// --- flow semantics ----------------------------------------------------

// --- rule validation ---------------------------------------------------

func TestRuleValidation(t *testing.T) {
	rule, err := LoadRuleBytes([]byte(ruleJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := rule.Validate(demoRegistry()); err != nil {
		t.Fatalf("valid rule should pass: %v", err)
	}

	// unknown capability
	bad := *rule
	bad.Capability = "admin:purge"
	if err := bad.Validate(demoRegistry()); err == nil {
		t.Fatalf("unknown capability must fail")
	}

	// row_filter column outside the column allowlist
	leak := *rule
	leak.Params = []byte(`{"tables":["customers"],"columns":{"customers":["id"]},
		"row_filter":{"customers":{"column":"ssn","op":"=","value":"x"}}}`)
	if err := leak.Validate(demoRegistry()); err == nil {
		t.Fatalf("row_filter referencing unallowed column must fail")
	}

	// limit out of range
	lim := *rule
	lim.Params = []byte(`{"tables":["customers"],"columns":{"customers":["id"]},"limit":{"max":100000000}}`)
	if err := lim.Validate(demoRegistry()); err == nil {
		t.Fatalf("oversized limit must fail")
	}
}

// --- signature ---------------------------------------------------------

func TestSignatureRoundtrip(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.json")
	if err := os.WriteFile(rulePath, []byte(ruleJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, cert, err := genSignerForRules(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	p7s := rulePath + ".p7s"
	if err := register.SignCapability(certPath, keyPath, rulePath, p7s); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := register.VerifyCapabilityPKCS7(rulePath, []*x509.Certificate{cert}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// tamper: any modification must break the signature
	if err := os.WriteFile(rulePath, append([]byte(ruleJSON), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := register.VerifyCapabilityPKCS7(rulePath, []*x509.Certificate{cert}); err == nil {
		t.Fatalf("tampered rule must fail verification")
	}
}

func TestValidateStructure(t *testing.T) {
	rule, err := LoadRuleBytes([]byte(ruleJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateStructure(rule); err != nil {
		t.Fatalf("valid rule structure should pass: %v", err)
	}
	badVer := *rule
	badVer.Version = "1.0"
	if err := ValidateStructure(&badVer); err == nil {
		t.Fatalf("non-semver version must fail")
	}
	badCond := *rule
	badCond.Conditions = &Condition{Op: "bogus"}
	if err := ValidateStructure(&badCond); err == nil {
		t.Fatalf("unknown condition op must fail")
	}
	badStep := *rule
	badStep.Flow = &Flow{Steps: []Step{{Kind: "teleport"}}}
	if err := ValidateStructure(&badStep); err == nil {
		t.Fatalf("unknown step kind must fail")
	}
}

func TestBudgetDefaults(t *testing.T) {
	def, err := LoadBudgetDefaults("budget-defaults.json")
	if err != nil {
		t.Fatalf("load defaults: %v", err)
	}
	if def.MaxSteps != 10000 {
		t.Fatalf("unexpected defaults: %+v", def)
	}
	b := BudgetFromDefaults(def)
	if b.MaxSteps != 10000 {
		t.Fatalf("budget not built from defaults: %+v", b)
	}
}

func TestPhaseTwoExecutor(t *testing.T) {
	rule, err := LoadRuleBytes([]byte(ruleJSON))
	if err != nil {
		t.Fatal(err)
	}
	ex := &RuleExecutor{
		Rule:    rule,
		Budget:  NewBudget(),
		Handler: demoHandler,
	}
	// conditions satisfied -> allow
	dec, err := ex.Decide(DecisionInput{
		AgentID: "agent:db-analyst-01", PrincipalID: "zhangsan", Mode: "authorized",
		EffectiveCaps: []string{"std/database-v1:query:SELECT"},
		Request: map[string]any{
			"tenant_id": "org-a",
			"time":      "2026-08-23T10:00:00Z",
			"params":    map[string]any{"amount": float64(500)},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dec.Allow {
		t.Fatalf("expected allow, got %+v", dec)
	}
	// tenant mismatch -> conditions not satisfied
	dec2, err := ex.Decide(DecisionInput{
		Request: map[string]any{
			"tenant_id": "org-b",
			"time":      "2026-08-23T10:00:00Z",
			"params":    map[string]any{"amount": float64(500)},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec2.Allow {
		t.Fatalf("expected deny for wrong tenant")
	}
	// excessive nesting -> static bounds error (loops and retries were
	// removed from the execution language on 2026-09-10; nesting depth is
	// the remaining statically-checked structural axis)
	deep := []Step{{Kind: "op", Op: "noop"}}
	for i := 0; i < 100; i++ {
		deep = []Step{{Kind: "seq", Steps: deep}}
	}
	badRule := *rule
	badRule.Flow = &Flow{Steps: deep}
	ex2 := &RuleExecutor{Rule: &badRule, Budget: NewBudget(), Handler: demoHandler}
	if _, err := ex2.Decide(DecisionInput{Request: map[string]any{"flag": true}}); err == nil {
		t.Fatalf("excessive nesting must be rejected by phase-two static bounds")
	}

}
func TestHTTPRequestMapping(t *testing.T) {
	// rule with HTTP conditions: method + header + query presence
	rule, err := LoadRuleBytes([]byte(`{
		"rule_id": "http-1", "version": "1.0.0",
		"scheme": "std/database-v1", "capability": "query:SELECT",
		"params": {"tables": ["customers"], "columns": {"customers": ["id"]}},
		"conditions": {"op": "and", "items": [
			{"op": "eq", "path": "request.method", "value": "GET"},
			{"op": "eq", "path": "request.headers.x-role", "value": "readonly"},
			{"op": "not", "items": [{"op": "is-null", "path": "request.query.tenant"}]}
		]}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	ex := &RuleExecutor{Rule: rule, Budget: NewBudget(), Handler: demoHandler}

	okCtx := &pki.PluginContext{
		AgentId:  "agent:db-analyst-01",
		ClientCN: "zhangsan",
		Target:   "query:SELECT",
		Method:   "GET",
		Path:     "/api/customers",
		Query:    map[string][]string{"tenant": {"org-a"}},
		Headers:  map[string]string{"x-role": "readonly"},
	}
	dec, err := ex.Decide(DecisionInput{
		AgentID: okCtx.AgentId, PrincipalID: okCtx.ClientCN, Mode: "authorized",
		EffectiveCaps: []string{"std/database-v1:query:SELECT"},
		Request:       MapHTTPRequest(okCtx),
	})
	if err != nil {
		t.Fatalf("expected allow: %v", err)
	}
	if !dec.Allow {
		t.Fatalf("GET with readonly role should be allowed")
	}

	// POST must be denied
	postCtx := *okCtx
	postCtx.Method = "POST"
	dec2, err := ex.Decide(DecisionInput{Request: MapHTTPRequest(&postCtx)})
	if err != nil {
		t.Fatal(err)
	}
	if dec2.Allow {
		t.Fatalf("POST must be denied by the rule")
	}
}
