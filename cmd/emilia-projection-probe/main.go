// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command emilia-projection-probe maps EMILIA's evidence-side objects into the
// CLC evidence projection and evaluates them, so the mapping is tested rather
// than asserted.
//
// Inputs are taken from the published drafts (checked 2026-10-17):
//   - EP-AEC-REQUIREMENT-v1 example: draft-schrock-ep-authorization-evidence-chain-08 §4
//   - facts a native verifier would produce: AEB-07 §5.2/§5.6 terms
//   - action identity: draft-schrock-canonical-action-identifier-05 §4.7 (tool.call.1)
//
// It prints one line per probe: what was mapped, what CLC decided, and what the
// mapping could not carry (residuals).
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/varwof/register/semantics"
)

// aecRequirement mirrors the EP-AEC-REQUIREMENT-v1 example in AEC-08 §4.
type aecRequirement struct {
	Version         string         `json:"@version"`
	RequirementID   string         `json:"requirement_id"`
	Purpose         string         `json:"purpose"`
	Expression      string         `json:"expression"`
	FreshnessSec    map[string]int `json:"freshness_sec"`
	StatusRequired  []string       `json:"status_required"`
	RoleConstraints []struct {
		Type          string `json:"type"`
		ComponentType string `json:"component_type"`
		Threshold     int    `json:"threshold"`
		SubjectSource string `json:"subject_id_source"`
	} `json:"role_constraints"`
	RequiredBindings []struct {
		FromType string `json:"from_type"`
		Relation string `json:"relation"`
		ToType   string `json:"to_type"`
	} `json:"required_bindings"`
}

type clcConstraint struct {
	Role       string `json:"role"`
	Constraint string `json:"constraint"`
}

type clcRequirement struct {
	Version       string          `json:"@version"`
	RequirementID string          `json:"requirement_id"`
	Expression    string          `json:"expression"`
	Constraints   []clcConstraint `json:"constraints,omitempty"`
}

const aecExample = `{
  "@version": "EP-AEC-REQUIREMENT-v1",
  "requirement_id": "treasury-wire-evidence@7",
  "purpose": "pre-execution evidence check",
  "expression": "ep-quorum AND policy-permit",
  "freshness_sec": {"ep-quorum": 300, "policy-permit": 600},
  "status_required": ["ep-quorum"],
  "role_constraints": [
    {"type": "distinct-subject-quorum", "component_type": "ep-human-authorization",
     "threshold": 2, "subject_id_source": "native-verifier"}
  ],
  "required_bindings": [
    {"from_type": "policy-permit", "relation": "permits", "to_type": "ep-quorum"}
  ]
}`

// mapRequirement projects the AEC object onto CLC-REQUIREMENT-v1.  It returns
// the mapped object and the list of things the projection could not carry.
func mapRequirement(a aecRequirement, quorumRole string) (clcRequirement, []string) {
	out := clcRequirement{
		Version:       "CLC-REQUIREMENT-v1",
		RequirementID: a.RequirementID,
		Expression:    a.Expression,
	}
	var residual []string

	roles := make([]string, 0, len(a.FreshnessSec))
	for r := range a.FreshnessSec {
		roles = append(roles, r)
	}
	sort.Strings(roles)
	for _, r := range roles {
		out.Constraints = append(out.Constraints, clcConstraint{
			Role:       r,
			Constraint: fmt.Sprintf("varwof/evidence-v1:freshness:sec:%d", a.FreshnessSec[r]),
		})
	}
	for _, rc := range a.RoleConstraints {
		if rc.Type != "distinct-subject-quorum" {
			residual = append(residual, "role_constraint "+rc.Type+": not expressible")
			continue
		}
		out.Constraints = append(out.Constraints, clcConstraint{
			Role:       quorumRole,
			Constraint: fmt.Sprintf("varwof/evidence-v1:quorum:distinct:%d", rc.Threshold),
		})
		if rc.ComponentType != quorumRole {
			residual = append(residual, fmt.Sprintf(
				"quorum role mapped from component_type %q, but the expression names %q",
				rc.ComponentType, quorumRole))
		}
		if rc.SubjectSource != "" {
			residual = append(residual, "subject_id_source="+rc.SubjectSource+": carrier-owned")
		}
	}
	for _, r := range a.StatusRequired {
		residual = append(residual, "status_required["+r+"]: carrier-owned, no CLC constraint")
	}
	for _, b := range a.RequiredBindings {
		residual = append(residual, fmt.Sprintf(
			"required_binding %s -%s-> %s: a relation between facts is not expressible",
			b.FromType, b.Relation, b.ToType))
	}
	residual = append(residual, "purpose: descriptive, dropped")
	return out, residual
}

func facts(now time.Time, entities map[string][]struct {
	subject  string
	verified bool
	ago      time.Duration
}) []semantics.EvidenceFact {
	var out []semantics.EvidenceFact
	types := make([]string, 0, len(entities))
	for t := range entities {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		for _, e := range entities[t] {
			out = append(out, semantics.EvidenceFact{
				Type: t, Subject: e.subject, Verified: e.verified, IssuedAt: now.Add(-e.ago),
			})
		}
	}
	return out
}

func evaluate(req clcRequirement, fs []semantics.EvidenceFact, now time.Time) string {
	raw, _ := json.Marshal(req)
	r, err := semantics.ParseRequirement(raw)
	if err != nil {
		return "parse error: " + err.Error()
	}
	res, err := semantics.EvaluateRequirement(r, fs, semantics.EvidenceContext{Now: now})
	if err != nil {
		return "eval error: " + err.Error()
	}
	sat := res.Satisfaction()
	return fmt.Sprintf("%s/%s", sat.Verdict, sat.Reason)
}

func main() {
	var aec aecRequirement
	if err := json.Unmarshal([]byte(aecExample), &aec); err != nil {
		panic(err)
	}
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

	fmt.Println("EMILIA → CLC evidence projection probe")
	fmt.Println("AEC requirement: draft-schrock-ep-authorization-evidence-chain-08 §4")
	fmt.Println()

	mapped, residual := mapRequirement(aec, "ep-quorum")
	b, _ := json.MarshalIndent(mapped, "", "  ")
	fmt.Println("1. EP-AEC-REQUIREMENT-v1 → CLC-REQUIREMENT-v1")
	fmt.Println(string(b))
	fmt.Println("   residuals:")
	for _, r := range residual {
		fmt.Println("   - " + r)
	}
	fmt.Println()

	type ent = struct {
		subject  string
		verified bool
		ago      time.Duration
	}
	cases := []struct {
		name   string
		facts  map[string][]ent
		expect string
	}{
		{"two verified approvals + one permit", map[string][]ent{
			"ep-quorum":     {{"alice", true, 30 * time.Second}, {"bob", true, 20 * time.Second}},
			"policy-permit": {{"policy", true, 60 * time.Second}},
		}, "SATISFIED"},
		{"one approval unverified", map[string][]ent{
			"ep-quorum":     {{"alice", true, 30 * time.Second}, {"bob", false, 20 * time.Second}},
			"policy-permit": {{"policy", true, 60 * time.Second}},
		}, "UNSATISFIED"},
		{"approval older than 300s", map[string][]ent{
			"ep-quorum":     {{"alice", true, 301 * time.Second}, {"bob", true, 20 * time.Second}},
			"policy-permit": {{"policy", true, 60 * time.Second}},
		}, "UNSATISFIED"},
		{"facts typed ep-human-authorization (literal component_type)", map[string][]ent{
			"ep-human-authorization": {{"alice", true, 30 * time.Second}, {"bob", true, 20 * time.Second}},
			"policy-permit":          {{"policy", true, 60 * time.Second}},
		}, "UNSATISFIED"},
	}
	fmt.Println("2. CLC evaluation over projected facts (§10)")
	for i, c := range cases {
		got := evaluate(mapped, facts(now, c.facts), now)
		verdict := strings.SplitN(got, "/", 2)[0]
		status := "PASS"
		if verdict != c.expect {
			status = "FAIL"
		}
		fmt.Printf("   %d) %-52s want %-11s got %-11s %s\n", i+1, c.name, c.expect, got, status)
	}
	fmt.Println()

	fmt.Println("3. CAID action identity → CLC §4.2 projection")
	def := semantics.ActionTypeDefinition{Type: "tool.call.1", MaterialFields: []string{"tool", "args"}}
	op := map[string]any{"tool": "payments.transfer", "args": map[string]any{"amount": 3000, "currency": "CNY"}}
	observedSame := map[string]any{"tool": "payments.transfer", "args": map[string]any{"amount": 3000, "currency": "CNY"}, "occurrence_id": "ignored-not-material"}
	observedDiff := map[string]any{"tool": "payments.transfer", "args": map[string]any{"amount": 3001, "currency": "CNY"}}
	opID, err := semantics.ComputeActionID(def, semantics.SuiteJCSSHA256, mustProject(def, op))
	if err != nil {
		panic(err)
	}
	for _, c := range []struct {
		name string
		act  map[string]any
		want string
	}{
		{"same tool+args, extra occurrence_id", observedSame, "MATCH"},
		{"args amount changed", observedDiff, "NOT_EQUIVALENT"},
	} {
		id, err := semantics.ComputeActionID(def, semantics.SuiteJCSSHA256, mustProject(def, c.act))
		got := "error"
		if err == nil {
			got = string(semantics.Match(id, opID))
		}
		status := "PASS"
		if got != c.want {
			status = "FAIL"
		}
		fmt.Printf("   %-40s want %-15s got %-15s %s\n", c.name, c.want, got, status)
	}
}

func mustProject(def semantics.ActionTypeDefinition, action map[string]any) map[string]any {
	p, err := semantics.MaterialProjection(def, action)
	if err != nil {
		panic(err)
	}
	return p
}
