// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Command gen-rule turns a validated capability claims file (the minimal set
// produced by gen-capability and consumed by `aic issue --from-claims`) into
// rule files for the execution layer.
//
// Usage: gen-rule -schemes <capability-data-dir> -claims <claims.json> [flags]
//
// For every claim it writes one rule file in the publication layout
//
//	<out>/<scheme>/v<major>.<minor>.json
//
// with the claim's capability and parameters, plus (optionally) the
// conditions / constraints / flow taken from a template rule.  Claims for the
// same scheme take ascending minor versions in file order.
//
// Nothing is written unless the generated rule passes both gates:
//
//   - LoadRuleBytes — structure, unknown fields rejected (fail-closed, so a
//     misspelled key cannot silently drop a constraint), and
//   - Rule.Validate — the capability exists in the registry and the parameters
//     satisfy that scheme's params_schema.
//
// The output is a skeleton: it carries authorization-relevant parameters but no
// runtime conditions unless a template supplies them.  Rules still have to be
// signed and published (`go run ./demo/rule-exec -publish`), and the loader
// additionally enforces that the rule stays inside the SIGNER's own AIC grant.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/varwof/register"
	"github.com/varwof/register/ruleexec"
)

type claim struct {
	SchemeID      string         `json:"scheme_id"`
	Capability    string         `json:"capability"`
	Parameters    map[string]any `json:"parameters,omitempty"`
	Rationale     string         `json:"rationale,omitempty"`
	SchemeVersion string         `json:"scheme_version,omitempty"`
}

func main() {
	var (
		schemesDir = flag.String("schemes", "", "capability data directory (required)")
		claimsPath = flag.String("claims", "", "validated capability claims JSON (required)")
		outDir     = flag.String("out", "rules", "output rules directory")
		version    = flag.String("version", "1.0", "initial rule version <major>.<minor>")
		template   = flag.String("template", "", "optional rule JSON supplying conditions / constraints / flow")
		force      = flag.Bool("force", false, "overwrite existing rule files")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: gen-rule -schemes <capability-data-dir> -claims <claims.json> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "从 gen-capability 校验过的最小能力清单生成规则文件骨架，写入 <out>/<scheme>/v<major>.<minor>.json。\n")
		fmt.Fprintf(os.Stderr, "每条 claim 一份；同一 scheme 的多条 claim 依次占用递增 minor。\n")
		fmt.Fprintf(os.Stderr, "生成结果必须通过结构校验（未知字段拒绝）与 scheme params_schema 校验，否则不写任何文件。\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *schemesDir == "" || *claimsPath == "" {
		flag.Usage()
		os.Exit(2)
	}

	major, minor, err := parseVersion(*version)
	if err != nil {
		fatal(err)
	}

	raw, err := os.ReadFile(*claimsPath)
	if err != nil {
		fatal(fmt.Errorf("read claims: %w", err))
	}
	var claims []claim
	if err := json.Unmarshal(raw, &claims); err != nil {
		fatal(fmt.Errorf("parse claims: %w", err))
	}
	if len(claims) == 0 {
		fatal(fmt.Errorf("claims file is empty"))
	}

	reg, err := register.NewRegistryFromDisk(*schemesDir)
	if err != nil {
		fatal(fmt.Errorf("load capability schemes from %s: %w", *schemesDir, err))
	}

	// Optional template: only the runtime half is taken from it.
	var tpl *ruleexec.Rule
	if *template != "" {
		t, err := ruleexec.LoadRule(*template)
		if err != nil {
			fatal(fmt.Errorf("template: %w", err))
		}
		tpl = t
	}

	plan, err := buildPlan(claims, reg, tpl, major, minor, *outDir)
	if err != nil {
		fatal(err)
	}

	// All claims validated: now write (or refuse) — never a partial output.
	for _, p := range plan {
		if _, err := os.Stat(p.path); err == nil && !*force {
			fatal(fmt.Errorf("%s exists (use -force to overwrite)", p.path))
		}
	}
	written := map[string]int{}
	multi := map[string]bool{}
	for _, p := range plan {
		if err := os.MkdirAll(filepath.Dir(p.path), 0o755); err != nil {
			fatal(err)
		}
		data, err := json.MarshalIndent(p.rule, "", "  ")
		if err != nil {
			fatal(err)
		}
		if err := os.WriteFile(p.path, append(data, '\n'), 0o644); err != nil {
			fatal(err)
		}
		written[p.claim.SchemeID]++
		if written[p.claim.SchemeID] > 1 {
			multi[p.claim.SchemeID] = true
		}
		fmt.Printf("%s  (%s:%s)\n", p.path, p.claim.SchemeID, p.claim.Capability)
	}

	fmt.Printf("\n生成 %d 条规则，覆盖 %d 个 scheme。\n", len(plan), len(written))
	for scheme := range multi {
		fmt.Fprintf(os.Stderr,
			"警告: %s 生成了多条规则，但注册时每个 scheme 只加载最高 minor 作为 default.json"+
				"（RegisterRulePluginsFromDir）；需要多条规则请拆分为不同 scheme，或改用模板把策略合并进一条规则。\n", scheme)
	}
	fmt.Println("下一步: go run ./demo/rule-exec -publish <out-dir> -out <publish-dir>  # 结构校验 + PKCS#7 签名")
}

func parseVersion(v string) (int, int, error) {
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("version must be <major>.<minor>, got %q", v)
	}
	var major, minor int
	if _, err := fmt.Sscanf(parts[0], "%d", &major); err != nil {
		return 0, 0, fmt.Errorf("bad major in %q", v)
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &minor); err != nil {
		return 0, 0, fmt.Errorf("bad minor in %q", v)
	}
	return major, minor, nil
}

// ruleID builds a stable, readable rule id within the 1..128 byte limit.
func ruleID(scheme, capability string, major, minor int) string {
	r := strings.NewReplacer("/", "-", ":", "-", " ", "-", "_", "-")
	id := fmt.Sprintf("%s-%s-v%d.%d", r.Replace(scheme), r.Replace(capability), major, minor)
	if len(id) > 128 {
		id = id[:128]
	}
	return id
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	os.Exit(1)
}

// planned is one validated rule file waiting to be written.
type planned struct {
	path  string
	rule  *ruleexec.Rule
	claim claim
}

// buildPlan turns claims into rule files, gated twice: LoadRuleBytes
// (structure, unknown fields rejected) and Rule.Validate (capability exists in
// the registry and the parameters satisfy that scheme's params_schema).  If any
// claim fails, no rule is returned — the caller writes nothing.
//
// Claims for the same scheme take ascending minor versions in file order.
func buildPlan(claims []claim, reg *register.Registry, tpl *ruleexec.Rule,
	major, minor int, outDir string) ([]planned, error) {

	var plan []planned
	minorByScheme := map[string]int{}

	for i, c := range claims {
		if c.SchemeID == "" || c.Capability == "" {
			return nil, fmt.Errorf("claim[%d]: scheme_id and capability are required", i)
		}
		m := minor
		if used, ok := minorByScheme[c.SchemeID]; ok {
			m = used + 1
		}
		minorByScheme[c.SchemeID] = m

		rule := &ruleexec.Rule{
			RuleID:     ruleID(c.SchemeID, c.Capability, major, m),
			Version:    fmt.Sprintf("%d.%d.0", major, m),
			Scheme:     c.SchemeID,
			Capability: c.Capability,
		}
		if c.Parameters != nil {
			b, err := json.Marshal(c.Parameters)
			if err != nil {
				return nil, fmt.Errorf("claim[%d] parameters: %w", i, err)
			}
			rule.Params = b
		} else {
			rule.Params = json.RawMessage("{}")
		}
		if tpl != nil {
			rule.Conditions = tpl.Conditions
			rule.Constraints = tpl.Constraints
			rule.Flow = tpl.Flow
		}

		data, err := json.MarshalIndent(rule, "", "  ")
		if err != nil {
			return nil, err
		}
		// Gate 1: structure + unknown fields.
		checked, err := ruleexec.LoadRuleBytes(data)
		if err != nil {
			return nil, fmt.Errorf("claim[%d] %s:%s: %w", i, c.SchemeID, c.Capability, err)
		}
		// Gate 2: registry capability + scheme params_schema.
		if err := checked.Validate(reg); err != nil {
			return nil, fmt.Errorf("claim[%d] %s:%s: %w", i, c.SchemeID, c.Capability, err)
		}

		path := filepath.Join(outDir, c.SchemeID, fmt.Sprintf("v%d.%d.json", major, m))
		plan = append(plan, planned{path: path, rule: checked, claim: c})
	}
	return plan, nil
}
