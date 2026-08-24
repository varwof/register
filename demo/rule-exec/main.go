package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/varwof/register"
	"github.com/varwof/register/ruleexec"
)

// ruleJSON is the demo rule (database-v1 contract, org-a).
const ruleJSON = `{
  "rule_id": "org-a-db-readonly-2026",
  "version": "1.0.0",
  "scheme": "std/database-v1",
  "capability": "query:SELECT",
  "params": {
    "tables": ["customers"],
    "columns": { "customers": ["id", "name"] },
    "filter_columns": { "customers": ["tenant_id"] },
    "row_filter": {
      "customers": { "and": [ { "column": "tenant_id", "op": "=", "value": "org-a" } ] }
    },
    "limit": { "max": 100 }
  },
  "conditions": {
    "op": "and",
    "items": [
      { "op": "eq", "path": "request.tenant_id", "value": "org-a" },
      { "op": "time-in", "path": "request.time", "window": ["08:00", "22:00"] },
      { "op": "lte", "path": "request.params.amount", "value": 1000 }
    ]
  },
  "roles": ["readonly"],
  "constraints": [
    { "scheme": "varwof/constraint-v1", "id": "allowed-cidr", "params": ["10.0.0.0/8"] }
  ],
  "flow": {
    "steps": [
      { "name": "query", "kind": "op", "op": "db:select" },
      { "kind": "if", "condition": { "op": "gt", "path": "rowCount", "value": 0 },
        "then": [ { "name": "mark", "kind": "op", "op": "db:update" } ] },
      { "name": "notify", "kind": "retry", "max_retries": 2,
        "steps": [ { "kind": "op", "op": "db:notify" } ] }
    ]
  }
}`

func main() {
	sqlOnly := flag.Bool("sql", false, "print generated MySQL SQL for the demo rule and exit")
	publishDir := flag.String("publish", "", "publish rules from this dir (rules/<scheme>/vX.Y.json)")
	outDir := flag.String("out", "/tmp/aic-rules", "publish output dir")
	flag.Parse()

	if *publishDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			fatal(err)
		}
		certPath, keyPath, _, err := ruleexec.GenSignerCert(*outDir)
		if err != nil {
			fatal(err)
		}
		manifest, err := ruleexec.PublishRules(*publishDir, *outDir, certPath, keyPath)
		if err != nil {
			fatal(err)
		}
		out, err := ruleexec.PublishManifestJSON(manifest)
		if err != nil {
			fatal(err)
		}
		fmt.Println(out)
		return
	}

	fmt.Println("=== AIC rule-exec 端到端 demo（探索验证）===")

	rule, err := ruleexec.LoadRuleBytes([]byte(ruleJSON))
	if err != nil {
		fatal(err)
	}
	fmt.Printf("规则校验通过: %s v%s (%s:%s)\n", rule.RuleID, rule.Version, rule.Scheme, rule.Capability)

	if *sqlOnly {
		sql, err := ruleexec.GenerateSelectSQL(rule.Params)
		if err != nil {
			fatal(err)
		}
		fmt.Println(sql)
		return
	}

	tmp, err := os.MkdirTemp("", "rule-exec-*")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(tmp)
	rulePath := filepath.Join(tmp, "rule.json")
	if err := os.WriteFile(rulePath, []byte(ruleJSON), 0o644); err != nil {
		fatal(err)
	}
	certPath, keyPath, cert, err := ruleexec.GenSignerCert(tmp)
	if err != nil {
		fatal(err)
	}
	if err := register.SignCapability(certPath, keyPath, rulePath, rulePath+".p7s"); err != nil {
		fatal(fmt.Errorf("sign: %w", err))
	}
	if err := register.VerifyCapabilityPKCS7(rulePath, []*x509.Certificate{cert}); err != nil {
		fatal(fmt.Errorf("verify signature: %w", err))
	}
	fmt.Println("PKCS#7 签名签发与验证通过")

	defaults, err := ruleexec.LoadBudgetDefaults("demo/rule-exec/budget-defaults.json")
	if err != nil {
		if defaults, err = ruleexec.LoadBudgetDefaults("budget-defaults.json"); err != nil {
			fatal(err)
		}
	}
	budget := ruleexec.BudgetFromDefaults(defaults)
	budget.Deadline = time.Now().Add(5 * time.Second)
	if err := ruleexec.CheckStaticBounds(*rule.Flow, budget); err != nil {
		fatal(err)
	}
	fmt.Println("静态流程边界预检通过")

	req := map[string]any{
		"tenant_id": "org-a",
		"time":      "2026-08-23T10:00:00Z",
		"params":    map[string]any{"amount": json.Number("500")},
	}
	evalCtx := map[string]any{"request": req}
	ok, err := ruleexec.EvalCondition(*rule.Conditions, evalCtx, budget, 0)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("条件求值: %v (steps=%d)\n", ok, budget.Steps())

	flowCtx := &ruleexec.FlowContext{
		Vars:    map[string]any{},
		Request: req,
		Handler: demoHandler,
	}
	if err := ruleexec.RunFlow(*rule.Flow, flowCtx, budget); err != nil {
		fatal(err)
	}
	steps, iters := budget.Stats()
	fmt.Printf("流程执行完成: rowCount=%v updated=%v (steps=%d, iterations=%d)\n",
		flowCtx.Vars["rowCount"], flowCtx.Vars["updated"], steps, iters)
	fmt.Println("=== 端到端闭环验证通过：规则 → 签名 → 校验 → 条件 → 流程 ===")
}

func demoHandler(op string, vars, req map[string]any) (map[string]any, error) {
	switch op {
	case "db:select":
		return map[string]any{"rowCount": 3}, nil
	case "db:update":
		if n, _ := vars["rowCount"].(int); n <= 0 {
			return nil, fmt.Errorf("no rows to update")
		}
		return map[string]any{"updated": true}, nil
	case "db:notify":
		return nil, nil
	}
	return nil, fmt.Errorf("unknown op %q", op)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "失败:", err)
	os.Exit(1)
}
