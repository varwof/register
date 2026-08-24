package ruleexec

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/varwof/register"
)

// TestMySQLScenarioV2 is the new-spec MySQL end-to-end scenario:
// signed rule -> validation -> conditions -> SQL generation -> flow,
// plus a multi-user permission matrix.
func TestMySQLScenarioV2(t *testing.T) {
	dir := t.TempDir()

	// 1) rule + scheme validation + PKCS#7 signing
	rule, err := LoadRuleBytes([]byte(ruleJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := rule.Validate(demoRegistry()); err != nil {
		t.Fatalf("rule validate: %v", err)
	}
	rulePath := filepath.Join(dir, "rule.json")
	if err := os.WriteFile(rulePath, []byte(ruleJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, cert, err := GenSignerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := register.SignCapability(certPath, keyPath, rulePath, rulePath+".p7s"); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := register.VerifyCapabilityPKCS7(rulePath, []*x509.Certificate{cert}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// 2) SQL generation (the MySQL translator)
	sql, err := GenerateSelectSQL(rule.Params)
	if err != nil {
		t.Fatalf("sql: %v", err)
	}
	want := "SELECT `id`, `name` FROM `customers` WHERE (`tenant_id` = 'org-a') LIMIT 100"
	if sql != want {
		t.Fatalf("sql mismatch:\n got: %s\nwant: %s", sql, want)
	}

	// 3) conditions + flow through the phase-two executor
	ex := &RuleExecutor{Rule: rule, Budget: NewBudget(), Handler: demoHandler}
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
		t.Fatalf("decide: %v", err)
	}
	if !dec.Allow || dec.Steps == 0 {
		t.Fatalf("expected allow with steps, got %+v", dec)
	}

	// 4) permission matrix: 张三 vs 李四 vs 越权列 vs 错租户
	zhang := sqlForParams(t, `{"tables":["customers"],"columns":{"customers":["id","name"]},
		"filter_columns":{"customers":["tenant_id"]},
		"row_filter":{"customers":{"column":"tenant_id","op":"=","value":"org-a"}},
		"limit":{"max":100}}`)
	li := sqlForParams(t, `{"tables":["customers"],"columns":{"customers":["id","name","email"]},
		"filter_columns":{"customers":["tenant_id"]},
		"row_filter":{"customers":{"column":"tenant_id","op":"=","value":"org-b"}},
		"limit":{"max":50}}`)
	if zhang == li {
		t.Fatalf("different users must produce different SQL")
	}
	if !jsonContains(zhang, "org-a") || !jsonContains(li, "org-b") {
		t.Fatalf("tenant isolation missing: zhang=%s li=%s", zhang, li)
	}
	if jsonContains(zhang, "`email`") {
		t.Fatalf("zhang must not see email column: %s", zhang)
	}

	// 越权列：Agent 声明 ssn，不在 grant 列内 -> 子集检查拒绝
	if columnsSubset([]string{"id", "name", "ssn"}, []string{"id", "name"}) {
		t.Fatalf("ssn must not be a subset of grant columns")
	}
	if !columnsSubset([]string{"id", "name"}, []string{"id", "name", "email"}) {
		t.Fatalf("grant columns must contain declared columns")
	}

	// 错租户：条件不满足 -> deny
	dec2, err := ex.Decide(DecisionInput{Request: map[string]any{
		"tenant_id": "org-b", "time": "2026-08-23T10:00:00Z",
		"params": map[string]any{"amount": float64(500)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if dec2.Allow {
		t.Fatalf("wrong tenant must be denied")
	}
}

func sqlForParams(t *testing.T, raw string) string {
	t.Helper()
	rule, err := LoadRuleBytes([]byte(`{
		"rule_id": "m", "version": "1.0.0",
		"scheme": "std/database-v1", "capability": "query:SELECT",
		"params": ` + raw + `
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := rule.Validate(demoRegistry()); err != nil {
		t.Fatal(err)
	}
	sql, err := GenerateSelectSQL(rule.Params)
	if err != nil {
		t.Fatal(err)
	}
	return sql
}

func jsonContains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// columnsSubset reports whether declared columns are within the grant
// column set (plain string set semantics; wildcards handled elsewhere).
func columnsSubset(declared, grant []string) bool {
	set := make(map[string]bool, len(grant))
	for _, c := range grant {
		set[c] = true
	}
	for _, c := range declared {
		if !set[c] {
			return false
		}
	}
	return true
}
