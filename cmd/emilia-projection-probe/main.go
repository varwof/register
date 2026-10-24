// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command emilia-projection-probe maps EMILIA's evidence-side objects into the
// CLC evidence projection and evaluates them, so the mapping is tested rather
// than asserted.
//
// Inputs are taken from the published drafts (checked 2026-10-17):
//   - EP-AEC-REQUIREMENT-v1 example: draft-schrock-ep-authorization-evidence-chain-08 §4
//   - facts a native verifier would produce: AEB-07 §5.2/§5.6 terms
//   - action shape: draft-schrock-canonical-action-identifier-05 §4.7
//     (tool.call.1); this probe checks CLC's independent material projection
//     and does not claim to parse or map a CAID wire identifier
//
// It prints one line per probe: what was mapped, what CLC decided, and what the
// mapping could not carry (residuals).
package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/varwof/register/projection"
	"github.com/varwof/register/semantics"
)

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

func digestJSON(v any) string {
	raw, err := semantics.CanonicalJSON(v)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type bindingFixture struct {
	Source  map[string]any   `json:"source"`
	Targets []map[string]any `json:"targets"`
	Action  map[string]any   `json:"action"`
	Status  map[string]any   `json:"status"`
	Trust   map[string]any   `json:"trust"`
}

type bindingMutation struct {
	Path  []any `json:"path"`
	Value any   `json:"value"`
}

type bindingFixtureDocument struct {
	Now               string                     `json:"now"`
	ExpectedSubject   string                     `json:"expected_subject"`
	BindingRole       string                     `json:"binding_role"`
	MappedRequirement semantics.Requirement      `json:"mapped_requirement"`
	Binding           bindingFixture             `json:"binding"`
	Mutations         map[string]bindingMutation `json:"mutations"`
}

//go:embed testdata/emilia-binding-fixture-v1.json
var bindingFixtureJSON []byte

func loadBindingFixture() bindingFixtureDocument {
	var doc bindingFixtureDocument
	if err := json.Unmarshal(bindingFixtureJSON, &doc); err != nil {
		panic(err)
	}
	return doc
}

func baseBindingFixture() bindingFixture {
	return loadBindingFixture().Binding
}

func fixtureNow() time.Time {
	now, err := time.Parse(time.RFC3339, loadBindingFixture().Now)
	if err != nil {
		panic(err)
	}
	return now
}

func (f bindingFixture) tuple() map[string]any {
	subjects := make([]string, 0, len(f.Targets))
	issuedAt := []string{f.Source["issued_at"].(string)}
	for _, target := range f.Targets {
		subjects = append(subjects, target["subject"].(string))
		issuedAt = append(issuedAt, target["issued_at"].(string))
	}
	sort.Strings(subjects)
	sort.Strings(issuedAt)
	return map[string]any{
		"requirement_id":    "treasury-wire-evidence@7",
		"policy_generation": f.Source["policy_generation"],
		"from": map[string]any{
			"type":            "policy-permit",
			"artifact_digest": digestJSON(f.Source),
		},
		"relation": "permits",
		"to": map[string]any{
			"type":                "ep-quorum",
			"artifact_set_digest": digestJSON(f.Targets),
		},
		"action_digest":      digestJSON(f.Action),
		"subjects":           subjects,
		"trust":              f.Trust,
		"status_digest":      digestJSON(f.Status),
		"status_snapshot":    f.Status,
		"evidence_issued_at": issuedAt,
	}
}

func bindingSubject(f bindingFixture) string {
	raw, err := semantics.CanonicalJSON(f.tuple())
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func mutatedBindingFixture(kind string) bindingFixture {
	doc := loadBindingFixture()
	f := doc.Binding
	mutation, ok := doc.Mutations[kind]
	if !ok {
		panic("unknown binding mutation: " + kind)
	}
	switch kind {
	case "source":
		f.Source[mutation.Path[1].(string)] = mutation.Value
	case "target":
		index := int(mutation.Path[1].(float64))
		f.Targets[index][mutation.Path[2].(string)] = mutation.Value
	case "action":
		f.Action[mutation.Path[1].(string)].(map[string]any)[mutation.Path[2].(string)] = mutation.Value
	case "status":
		f.Status[mutation.Path[1].(string)] = mutation.Value
	default:
		panic("unknown binding mutation: " + kind)
	}
	return f
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

func evaluate(req semantics.Requirement, fs []semantics.EvidenceFact, now time.Time) string {
	res, err := semantics.EvaluateRequirement(req, fs, semantics.EvidenceContext{Now: now})
	if err != nil {
		return "eval error: " + err.Error()
	}
	sat := res.Satisfaction()
	if sat.Reason == "" {
		return string(sat.Verdict)
	}
	return fmt.Sprintf("%s/%s", sat.Verdict, sat.Reason)
}

func main() {
	now := fixtureNow()

	fmt.Println("EMILIA → CLC evidence projection probe")
	fmt.Println("AEC requirement: draft-schrock-ep-authorization-evidence-chain-08 §4")
	fmt.Println()

	projected, err := projection.Project([]byte(aecExample), projection.Options{
		Now: now,
		RoleMap: map[string]string{
			"ep-human-authorization": "ep-quorum",
			"ep-quorum":              "ep-quorum",
			"policy-permit":          "policy-permit",
		},
	})
	if err != nil {
		panic(err)
	}
	mapped := *projected.Requirement
	residual := projected.Residuals
	fixtureDoc := loadBindingFixture()
	mappedWant, _ := semantics.CanonicalJSON(fixtureDoc.MappedRequirement)
	mappedGot, _ := semantics.CanonicalJSON(mapped)
	if string(mappedGot) != string(mappedWant) {
		panic("mapped requirement differs from shared fixture")
	}
	b, _ := json.MarshalIndent(mapped, "", "  ")
	fmt.Println("1. EP-AEC-REQUIREMENT-v1 → CLC-REQUIREMENT-v1")
	fmt.Println(string(b))
	fmt.Println("   residuals:")
	for _, r := range residual {
		fmt.Println("   - " + r)
	}
	fmt.Println("   required native checks:")
	for _, r := range projected.RequiredNativeChecks {
		fmt.Println("   - " + r)
	}
	bindingRole, err := projection.BindingRoleName("policy-permit", "permits", "ep-quorum")
	if err != nil {
		panic(err)
	}
	if bindingRole != fixtureDoc.BindingRole {
		panic("binding role differs from shared fixture")
	}
	bindingFixture := baseBindingFixture()
	bindingTuple, _ := semantics.CanonicalJSON(bindingFixture.tuple())
	fmt.Printf("   derived binding role: %s\n", bindingRole)
	fmt.Printf("   relation tuple (JCS): %s\n", bindingTuple)
	fmt.Printf("   derived binding subject: %s\n", bindingSubject(bindingFixture))
	fmt.Println()

	type ent = struct {
		subject  string
		verified bool
		ago      time.Duration
	}
	baseBindingSubject := bindingSubject(bindingFixture)
	cases := []struct {
		caseID string
		name   string
		facts  map[string][]ent
		expect string
	}{
		{"EMI-AEC-001", "two verified approvals, permit and binding", map[string][]ent{
			"ep-quorum":     {{"alice", true, 30 * time.Second}, {"bob", true, 20 * time.Second}},
			"policy-permit": {{"policy", true, 60 * time.Second}},
			bindingRole:     {{baseBindingSubject, true, 60 * time.Second}},
		}, "SATISFIED"},
		{"EMI-AEC-002", "one approval unverified", map[string][]ent{
			"ep-quorum":     {{"alice", true, 30 * time.Second}, {"bob", false, 20 * time.Second}},
			"policy-permit": {{"policy", true, 60 * time.Second}},
			bindingRole:     {{baseBindingSubject, true, 60 * time.Second}},
		}, "UNSATISFIED"},
		{"EMI-AEC-003", "fresh binding does not refresh an old approval", map[string][]ent{
			"ep-quorum":     {{"alice", true, 301 * time.Second}, {"bob", true, 20 * time.Second}},
			"policy-permit": {{"policy", true, 60 * time.Second}},
			bindingRole:     {{baseBindingSubject, true, 1 * time.Second}},
		}, "UNSATISFIED"},
		{"EMI-AEC-004", "missing derived binding fact", map[string][]ent{
			"ep-quorum":     {{"alice", true, 30 * time.Second}, {"bob", true, 20 * time.Second}},
			"policy-permit": {{"policy", true, 60 * time.Second}},
		}, "UNSATISFIED"},
		{"EMI-AEC-005", "facts typed ep-human-authorization (literal component_type)", map[string][]ent{
			"ep-human-authorization": {{"alice", true, 30 * time.Second}, {"bob", true, 20 * time.Second}},
			"policy-permit":          {{"policy", true, 60 * time.Second}},
			bindingRole:              {{baseBindingSubject, true, 60 * time.Second}},
		}, "UNSATISFIED"},
	}
	fmt.Println("2. CLC evaluation over projected facts (§10)")
	for _, c := range cases {
		got := evaluate(mapped, facts(now, c.facts), now)
		verdict := strings.SplitN(got, "/", 2)[0]
		status := "PASS"
		if verdict != c.expect {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-52s want=%s got=%s\n", status, c.caseID, c.name, c.expect, got)
	}
	fmt.Println()

	fmt.Println("3. CLC material action identity (CAID parser/mapping not exercised)")
	def := semantics.ActionTypeDefinition{Type: "tool.call.1", MaterialFields: []string{"tool", "args"}}
	op := map[string]any{"tool": "payments.transfer", "args": map[string]any{"amount": 3000, "currency": "CNY"}}
	observedSame := map[string]any{"tool": "payments.transfer", "args": map[string]any{"amount": 3000, "currency": "CNY"}, "occurrence_id": "ignored-not-material"}
	observedDiff := map[string]any{"tool": "payments.transfer", "args": map[string]any{"amount": 3001, "currency": "CNY"}}
	opID, err := semantics.ComputeActionID(def, semantics.SuiteJCSSHA256, mustProject(def, op))
	if err != nil {
		panic(err)
	}
	for _, c := range []struct {
		caseID string
		name   string
		act    map[string]any
		want   string
	}{
		{"EMI-CAID-001", "CLC projection: extra non-material occurrence_id", observedSame, "MATCH"},
		{"EMI-CAID-002", "CLC projection: material args amount changed", observedDiff, "NOT_EQUIVALENT"},
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
		fmt.Printf("%s %s %-40s want=%s got=%s\n", status, c.caseID, c.name, c.want, got)
	}
	fmt.Println()

	fmt.Println("4. Binding identity derivation and boundary")
	fmt.Println("Fixtures: synthetic AEC-shaped artifacts, not production bytes")
	expectedBindingSubject := fixtureDoc.ExpectedSubject
	bindingCases := []struct {
		caseID string
		name   string
		want   string
		got    string
	}{
		{
			"EMI-BIND-001",
			"base relation tuple has the pinned subject",
			expectedBindingSubject,
			baseBindingSubject,
		},
	}
	for _, mutation := range []string{"source", "target", "action", "status"} {
		bindingCases = append(bindingCases, struct {
			caseID string
			name   string
			want   string
			got    string
		}{
			"EMI-BIND-00" + fmt.Sprint(len(bindingCases)+1),
			mutation + " mutation changes the relation subject",
			"different",
			map[bool]string{true: "different", false: "unchanged"}[bindingSubject(mutatedBindingFixture(mutation)) != baseBindingSubject],
		})
	}
	opaque := evaluate(mapped, facts(now, map[string][]ent{
		"ep-quorum":     {{"alice", true, 30 * time.Second}, {"bob", true, 20 * time.Second}},
		"policy-permit": {{"policy", true, 60 * time.Second}},
		bindingRole:     {{"arbitrary-unbound-subject", true, 60 * time.Second}},
	}), now)
	bindingCases = append(bindingCases, struct {
		caseID string
		name   string
		want   string
		got    string
	}{
		"EMI-BIND-006",
		"CLC treats the binding subject as opaque",
		"opaque-subject-accepted",
		map[bool]string{true: "opaque-subject-accepted", false: "unexpectedly-rejected"}[strings.SplitN(opaque, "/", 2)[0] == "SATISFIED"],
	})
	for _, c := range bindingCases {
		status := "PASS"
		if c.got != c.want {
			status = "FAIL"
		}
		fmt.Printf("%s %s %-55s want=%s got=%s\n", status, c.caseID, c.name, c.want, c.got)
	}
}

func mustProject(def semantics.ActionTypeDefinition, action map[string]any) map[string]any {
	p, err := semantics.MaterialProjection(def, action)
	if err != nil {
		panic(err)
	}
	return p
}
