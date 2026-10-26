// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/projection"
	"github.com/varwof/register/semantics"
)

const emiliaRequirement = `{
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

func emiliaRoleMap() map[string]string {
	return map[string]string{
		"ep-human-authorization": "ep-quorum",
		"ep-quorum":              "ep-quorum",
		"policy-permit":          "policy-permit",
	}
}

func TestProjectAECRequiredBindingAndNativeChecks(t *testing.T) {
	now := time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC)
	rep, err := projection.Project([]byte(emiliaRequirement), projection.Options{
		Now:     now,
		RoleMap: emiliaRoleMap(),
	})
	if err != nil {
		t.Fatalf("project AEC: %v", err)
	}
	bindingRole, err := projection.BindingRoleName("policy-permit", "permits", "ep-quorum")
	if err != nil {
		t.Fatal(err)
	}
	wantExpression := "(ep-quorum AND policy-permit) AND " + bindingRole
	if rep.Requirement.Expression != wantExpression {
		t.Fatalf("expression = %q, want %q", rep.Requirement.Expression, wantExpression)
	}
	if !slices.ContainsFunc(rep.RequiredNativeChecks, func(s string) bool {
		return s == "status_required:ep-quorum"
	}) {
		t.Fatalf("missing status check in %v", rep.RequiredNativeChecks)
	}
	if !slices.ContainsFunc(rep.RequiredNativeChecks, func(s string) bool {
		return strings.Contains(s, "required_binding:policy-permit:permits:ep-quorum")
	}) {
		t.Fatalf("missing binding check in %v", rep.RequiredNativeChecks)
	}
	if rep.Meta["mapped_at_utc"] != now.Format(time.RFC3339) {
		t.Errorf("mapped_at_utc = %q", rep.Meta["mapped_at_utc"])
	}
}

func TestProjectAECRequiresDerivedBindingFact(t *testing.T) {
	now := time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC)
	facts := []semantics.EvidenceFact{
		{Type: "ep-quorum", Subject: "alice", IssuedAt: now.Add(-30 * time.Second), Verified: true},
		{Type: "ep-quorum", Subject: "bob", IssuedAt: now.Add(-20 * time.Second), Verified: true},
		{Type: "policy-permit", Subject: "policy", IssuedAt: now.Add(-60 * time.Second), Verified: true},
	}
	rep, err := projection.Project([]byte(emiliaRequirement), projection.Options{
		Now:     now,
		RoleMap: emiliaRoleMap(),
		Facts:   facts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Satisfaction.Satisfaction().Verdict; got != semantics.SatisfactionUnsatisfied {
		t.Fatalf("without derived binding got %s, want UNSATISFIED", got)
	}

	bindingRole, err := projection.BindingRoleName("policy-permit", "permits", "ep-quorum")
	if err != nil {
		t.Fatal(err)
	}
	facts = append(facts, semantics.EvidenceFact{
		Type: bindingRole, Subject: "binding", IssuedAt: now.Add(-10 * time.Second), Verified: true,
	})
	rep, err = projection.Project([]byte(emiliaRequirement), projection.Options{
		Now:     now,
		RoleMap: emiliaRoleMap(),
		Facts:   facts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Satisfaction.Satisfaction().Verdict; got != semantics.SatisfactionSatisfied {
		t.Fatalf("with derived binding got %s, want SATISFIED", got)
	}
}

func TestProjectAECMapsEveryConstraintRole(t *testing.T) {
	doc := `{
		"@version":"EP-AEC-REQUIREMENT-v1",
		"requirement_id":"mapped@1",
		"expression":"ep-quorum",
		"freshness_sec":{"ep-human-authorization":30},
		"role_constraints":[
			{"type":"distinct-subject-quorum","component_type":"ep-human-authorization",
			 "threshold":2,"subject_id_source":"native-verifier"}
		]
	}`
	rep, err := projection.Project([]byte(doc), projection.Options{RoleMap: emiliaRoleMap()})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Requirement.Constraints {
		if c.Role != "ep-quorum" {
			t.Errorf("constraint %q mapped to %q, want ep-quorum", c.Constraint, c.Role)
		}
	}
}

func TestProjectAECRejectsUnsafeInputs(t *testing.T) {
	tests := map[string]string{
		"unknown role constraint": `{
			"@version":"EP-AEC-REQUIREMENT-v1","requirement_id":"x@1","expression":"a",
			"role_constraints":[{"type":"new-constraint","component_type":"a","threshold":2,
			 "subject_id_source":"native-verifier"}]
		}`,
		"unpinned role": `{
			"@version":"EP-AEC-REQUIREMENT-v1","requirement_id":"x@1","expression":"a",
			"freshness_sec":{"a":30}
		}`,
		"wrong subject source": `{
			"@version":"EP-AEC-REQUIREMENT-v1","requirement_id":"x@1","expression":"a",
			"role_constraints":[{"type":"distinct-subject-quorum","component_type":"a",
			 "threshold":2,"subject_id_source":"presenter"}]
		}`,
		"duplicate member": `{
			"@version":"EP-AEC-REQUIREMENT-v1","requirement_id":"x@1",
			"expression":"a","expression":"b"
		}`,
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := projection.Project([]byte(doc), projection.Options{RoleMap: emiliaRoleMap()}); err == nil {
				t.Fatal("unsafe AEC input was accepted")
			}
		})
	}
}

const emiliaORRequirement = `{
  "@version": "EP-AEC-REQUIREMENT-v1",
  "requirement_id": "or-evidence@1",
  "expression": "a OR b"
}`

func identityRoles(names ...string) map[string]string {
	m := make(map[string]string, len(names))
	for _, name := range names {
		m[name] = name
	}
	return m
}

func verifiedFact(role, subject string, now time.Time) semantics.EvidenceFact {
	return semantics.EvidenceFact{
		Type: role, Subject: subject, Verified: true, IssuedAt: now.Add(-time.Minute),
	}
}

func projectJSON(t *testing.T, rep any) string {
	t.Helper()
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	return string(raw)
}

// unavailableOutcomes filters the explicit results down to the unavailable
// ones, so a test can assert that a reason survived projection.
func unavailableOutcomes(rep *projection.Report) []projection.NativeCheckResult {
	var out []projection.NativeCheckResult
	for _, result := range rep.NativeCheckResults {
		if result.Outcome == projection.NativeCheckUnavailable {
			out = append(out, result)
		}
	}
	return out
}

// nativeResults builds an attributable result set for tests: one explicit
// record per requested (check, component, outcome).
func nativeResult(check, component string, outcome projection.NativeCheckOutcome, now time.Time) projection.NativeCheckResult {
	r := projection.NativeCheckResult{
		CheckID:               check,
		ComponentType:         component,
		EvidenceDigest:        projection.Digest("sha-256:" + strings.Repeat("a", 64)),
		Outcome:               outcome,
		Verifier:              "native-verifier/1",
		VerifierProfileDigest: projection.Digest("sha-256:" + strings.Repeat("b", 64)),
		TrustSnapshotDigest:   projection.Digest("sha-256:" + strings.Repeat("c", 64)),
		StatusSnapshotDigest:  projection.Digest("sha-256:" + strings.Repeat("d", 64)),
		VerificationTime:      now,
		FreshnessDecision:     &projection.FreshnessDecision{Verdict: projection.FreshnessFresh},
	}
	switch outcome {
	case projection.NativeCheckFailed:
		r.Reason = "emilia:revoked"
	case projection.NativeCheckUnavailable:
		r.Reason = "emilia:unavailable:timeout"
	case projection.NativeCheckNotApplicable:
		r.Reason = "emilia:not-applicable:no-status-material"
	}
	return r
}

// An unavailable branch under OR is not a failed requirement: the eligible
// branch decides, and the unavailable-input reason stays in the report.
func TestProjectAECORBranchUnavailableStillSatisfied(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	rep, err := projection.Project([]byte(emiliaORRequirement), projection.Options{
		Now:     now,
		RoleMap: identityRoles("a", "b"),
		Facts:   []semantics.EvidenceFact{verifiedFact("b", "bob", now)},
		NativeCheckResults: []projection.NativeCheckResult{
			nativeResult("status_required:a", "a", projection.NativeCheckUnavailable, now),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Satisfaction.Satisfaction().Verdict; got != semantics.SatisfactionSatisfied {
		t.Fatalf("verdict = %s, want SATISFIED", got)
	}
	if got := unavailableOutcomes(rep); len(got) != 1 ||
		got[0].ComponentType != "a" ||
		got[0].Reason != "emilia:unavailable:timeout" {
		t.Fatalf("unavailable reason was dropped: %+v", rep.NativeCheckResults)
	}
	if strings.Contains(projectJSON(t, rep), "allow_unresolved") {
		t.Fatal("native unavailability leaked the authorization-only allow_unresolved verdict")
	}
}

// An explicit role constraint is independent of the expression: even a
// satisfied OR branch does not excuse a declared constraint failure.
func TestProjectAECORDeclaredConstraintFailureStillFails(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	doc := `{
	  "@version": "EP-AEC-REQUIREMENT-v1",
	  "requirement_id": "or-constraint@1",
	  "expression": "a OR b",
	  "role_constraints": [
	    {"type": "distinct-subject-quorum", "component_type": "a",
	     "threshold": 2, "subject_id_source": "native-verifier"}
	  ]
	}`
	rep, err := projection.Project([]byte(doc), projection.Options{
		Now:     now,
		RoleMap: identityRoles("a", "b"),
		Facts:   []semantics.EvidenceFact{verifiedFact("b", "bob", now)},
		NativeCheckResults: []projection.NativeCheckResult{
			nativeResult("status_required:a", "a", projection.NativeCheckUnavailable, now),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Satisfaction.Expression {
		t.Fatal("test precondition: the OR expression should be satisfied by b")
	}
	sat := rep.Satisfaction.Satisfaction()
	if sat.Verdict != semantics.SatisfactionUnsatisfied {
		t.Fatalf("verdict = %s, want UNSATISFIED", sat.Verdict)
	}
	if !strings.Contains(sat.Reason, "quorum") {
		t.Fatalf("reason = %q, want the quorum constraint failure", sat.Reason)
	}
}

// A required binding adds a conjunctive term, so an unavailable source role
// cannot rescue the requirement through a sibling OR branch.
func TestProjectAECORRequiredBindingFailureStillFails(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	doc := `{
	  "@version": "EP-AEC-REQUIREMENT-v1",
	  "requirement_id": "or-binding@1",
	  "expression": "a OR b",
	  "required_bindings": [
	    {"from_type": "a", "relation": "issued", "to_type": "b"}
	  ]
	}`
	rep, err := projection.Project([]byte(doc), projection.Options{
		Now:     now,
		RoleMap: identityRoles("a", "b"),
		Facts:   []semantics.EvidenceFact{verifiedFact("b", "bob", now)},
		NativeCheckResults: []projection.NativeCheckResult{
			nativeResult("status_required:a", "a", projection.NativeCheckUnavailable, now),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	bindingRole, err := projection.BindingRoleName("a", "issued", "b")
	if err != nil {
		t.Fatal(err)
	}
	if want := "(a OR b) AND " + bindingRole; rep.Requirement.Expression != want {
		t.Fatalf("expression = %q, want %q", rep.Requirement.Expression, want)
	}
	if got := rep.Satisfaction.Satisfaction().Verdict; got != semantics.SatisfactionUnsatisfied {
		t.Fatalf("verdict = %s, want UNSATISFIED", got)
	}
}

func TestProjectAECORAllBranchesUnavailable(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	rep, err := projection.Project([]byte(emiliaORRequirement), projection.Options{
		Now:     now,
		RoleMap: identityRoles("a", "b"),
		NativeCheckResults: []projection.NativeCheckResult{
			nativeResult("status_required:a", "a", projection.NativeCheckUnavailable, now),
			nativeResult("status_required:b", "b", projection.NativeCheckUnavailable, now),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sat := rep.Satisfaction.Satisfaction()
	if sat.Verdict != semantics.SatisfactionUnsatisfied {
		t.Fatalf("verdict = %s, want UNSATISFIED", sat.Verdict)
	}
	if sat.Reason != semantics.SatisfactionReasonExpressionFalse {
		t.Fatalf("reason = %q, want %q", sat.Reason, semantics.SatisfactionReasonExpressionFalse)
	}
	if got := unavailableOutcomes(rep); len(got) != 2 {
		t.Fatalf("unavailable reasons = %+v, want both branches", rep.NativeCheckResults)
	}
}

func TestProjectAECRequiredBindingsAreConjunctive(t *testing.T) {
	doc := `{
	  "@version": "EP-AEC-REQUIREMENT-v1",
	  "requirement_id": "or-bindings@1",
	  "expression": "a OR b",
	  "required_bindings": [
	    {"from_type": "a", "relation": "issued", "to_type": "b"},
	    {"from_type": "b", "relation": "permits", "to_type": "c"}
	  ]
	}`
	rep, err := projection.Project([]byte(doc), projection.Options{
		RoleMap: identityRoles("a", "b", "c"),
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := projection.BindingRoleName("a", "issued", "b")
	if err != nil {
		t.Fatal(err)
	}
	second, err := projection.BindingRoleName("b", "permits", "c")
	if err != nil {
		t.Fatal(err)
	}
	want := "(a OR b) AND " + first + " AND " + second
	if rep.Requirement.Expression != want {
		t.Fatalf("expression = %q, want %q", rep.Requirement.Expression, want)
	}
}

func TestBindingRoleNameIsInjective(t *testing.T) {
	base, err := projection.BindingRoleName("a", "issued", "b")
	if err != nil {
		t.Fatal(err)
	}
	again, err := projection.BindingRoleName("a", "issued", "b")
	if err != nil {
		t.Fatal(err)
	}
	if base != again {
		t.Fatalf("same tuple produced %q and %q", base, again)
	}
	if !strings.HasPrefix(base, "clc:evidence-binding:") {
		t.Fatalf("role %q is outside the reserved namespace", base)
	}

	triples := [][3]string{
		{"a", "issued", "b"},
		{"a", "permits", "b"},
		{"a", "issued", "c"},
		{"b", "issued", "a"},
		{"a:b", "issued", "c"},
		{"a", "b:issued", "c"},
		{"a", "issued", "b:c"},
		{"a:b", "c", "d"},
		{"a", "b:c", "d"},
		{"a", "b", "c:d"},
	}
	seen := map[string][3]string{}
	for _, triple := range triples {
		role, err := projection.BindingRoleName(triple[0], triple[1], triple[2])
		if err != nil {
			t.Fatalf("BindingRoleName(%q): %v", triple, err)
		}
		if previous, ok := seen[role]; ok {
			t.Fatalf("triples %q and %q share role %q", previous, triple, role)
		}
		seen[role] = triple

		// The generated role must be a term the CLC bounded grammar accepts.
		doc := `{"@version":"CLC-REQUIREMENT-v1","requirement_id":"role@1","expression":"` + role + `"}`
		if _, err := semantics.ParseRequirement([]byte(doc)); err != nil {
			t.Fatalf("role %q does not parse as a CLC identifier: %v", role, err)
		}
	}
}

func TestBindingRoleNameRejectsOverLimitAndInvalidParts(t *testing.T) {
	long := strings.Repeat("a", 200)
	if role, err := projection.BindingRoleName(long, long, long); err == nil {
		t.Fatalf("over-limit triple produced a %d-byte role; want rejection", len(role))
	}
	for _, tc := range []struct {
		name               string
		from, relation, to string
	}{
		{"empty from", "", "issued", "b"},
		{"empty relation", "a", "", "b"},
		{"empty to", "a", "issued", ""},
		{"space", "a b", "issued", "c"},
		{"non-ASCII", "é", "issued", "c"},
		{"invalid UTF-8", string([]byte{0xff}), "issued", "c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := projection.BindingRoleName(tc.from, tc.relation, tc.to); err == nil {
				t.Fatal("invalid triple was accepted")
			}
		})
	}
}

// The role limit is not the only bound: the complete rewritten expression must
// still fit CLC's 512-byte expression limit.
func TestProjectAECRejectsOverlongProjectedExpression(t *testing.T) {
	bindings := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		bindings = append(bindings, fmt.Sprintf(
			`{"from_type":"a%d","relation":"issued","to_type":"b%d"}`, i, i))
	}
	doc := fmt.Sprintf(`{
	  "@version":"EP-AEC-REQUIREMENT-v1",
	  "requirement_id":"too-long@1",
	  "expression":"a OR b",
	  "required_bindings":[%s]
	}`, strings.Join(bindings, ","))
	if _, err := projection.Project([]byte(doc), projection.Options{
		RoleMap: identityRoles("a", "b"),
	}); err == nil {
		t.Fatal("projected requirement longer than CLC's expression limit was accepted")
	}
}

func recomputeSourceDigest(t *testing.T, doc string) semantics.Digest {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	var source any
	if err := dec.Decode(&source); err != nil {
		t.Fatal(err)
	}
	digest, err := semantics.DigestOf(source)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestProjectAECPreservesBothRequirementDigests(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	project := func(doc string) *projection.Report {
		t.Helper()
		rep, err := projection.Project([]byte(doc), projection.Options{
			Now:     now,
			RoleMap: emiliaRoleMap(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}

	first := project(emiliaRequirement)
	second := project(emiliaRequirement)
	if first.SourceRequirementDigest == nil || first.ProjectedRequirementDigest == nil {
		t.Fatal("projection did not report both requirement digests")
	}
	if !first.SourceRequirementDigest.Equal(*second.SourceRequirementDigest) ||
		!first.ProjectedRequirementDigest.Equal(*second.ProjectedRequirementDigest) {
		t.Fatal("digests are not stable across repeated projection")
	}

	// Each digest is independently recomputable from its own object.
	if want := recomputeSourceDigest(t, emiliaRequirement); !first.SourceRequirementDigest.Equal(want) {
		t.Fatalf("source digest = %+v, want %+v", *first.SourceRequirementDigest, want)
	}
	wantProjected, err := first.Requirement.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !first.ProjectedRequirementDigest.Equal(wantProjected) {
		t.Fatalf("projected digest = %+v, want %+v", *first.ProjectedRequirementDigest, wantProjected)
	}

	// A member that is report-only (status_required) changes the source digest
	// but not the projected CLC requirement.
	sourceOnly := strings.Replace(emiliaRequirement,
		`"status_required": ["ep-quorum"]`,
		`"status_required": ["policy-permit"]`, 1)
	if sourceOnly == emiliaRequirement {
		t.Fatal("test fixture did not change status_required")
	}
	changed := project(sourceOnly)
	if first.SourceRequirementDigest.Equal(*changed.SourceRequirementDigest) {
		t.Fatal("source digest did not change with the source object")
	}
	if !first.ProjectedRequirementDigest.Equal(*changed.ProjectedRequirementDigest) {
		t.Fatal("projected digest changed for a report-only source member")
	}

	// Changing the expression changes both the source and the projected object.
	expressionChanged := project(strings.Replace(emiliaRequirement,
		`"expression": "ep-quorum AND policy-permit"`,
		`"expression": "ep-quorum OR policy-permit"`, 1))
	if first.SourceRequirementDigest.Equal(*expressionChanged.SourceRequirementDigest) {
		t.Fatal("source digest did not change with the expression")
	}
	if first.ProjectedRequirementDigest.Equal(*expressionChanged.ProjectedRequirementDigest) {
		t.Fatal("projected digest did not change with the expression")
	}
}

// CLC satisfaction is a statement about the projected requirement, never a
// statement that a mandatory native status check ran.
func TestProjectAECStatusBoundary(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	doc := `{
	  "@version": "EP-AEC-REQUIREMENT-v1",
	  "requirement_id": "status@1",
	  "expression": "a",
	  "status_required": ["a"]
	}`
	rep, err := projection.Project([]byte(doc), projection.Options{
		Now:     now,
		RoleMap: identityRoles("a"),
		Facts:   []semantics.EvidenceFact{verifiedFact("a", "alice", now)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rep.RequiredNativeChecks, "status_required:a") {
		t.Fatalf("required status check missing from %v", rep.RequiredNativeChecks)
	}
	if got := rep.Satisfaction.Satisfaction().Verdict; got != semantics.SatisfactionSatisfied {
		t.Fatalf("verdict = %s, want SATISFIED over eligible facts", got)
	}

	unavailable, err := projection.Project([]byte(doc), projection.Options{
		Now:     now,
		RoleMap: identityRoles("a"),
		NativeCheckResults: []projection.NativeCheckResult{
			nativeResult("status_required:a", "a", projection.NativeCheckUnavailable, now),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := unavailable.Satisfaction.Satisfaction().Verdict; got != semantics.SatisfactionUnsatisfied {
		t.Fatalf("verdict without status input = %s, want UNSATISFIED", got)
	}
	if got := unavailableOutcomes(unavailable); len(got) != 1 ||
		got[0].Reason != "emilia:unavailable:timeout" {
		t.Fatalf("status unavailable reason was dropped: %+v", unavailable.NativeCheckResults)
	}
}

func TestProjectRejectsMalformedNativeCheckResults(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	valid := nativeResult("status_required:a", "a", projection.NativeCheckUnavailable, now)
	for name, mutate := range map[string]func(*projection.NativeCheckResult){
		"no check id":        func(r *projection.NativeCheckResult) { r.CheckID = "" },
		"no component":       func(r *projection.NativeCheckResult) { r.ComponentType = "" },
		"no evidence digest": func(r *projection.NativeCheckResult) { r.EvidenceDigest = "" },
		"no verifier":        func(r *projection.NativeCheckResult) { r.Verifier = "" },
		"no profile digest":  func(r *projection.NativeCheckResult) { r.VerifierProfileDigest = "" },
		"no verification time": func(r *projection.NativeCheckResult) {
			r.VerificationTime = time.Time{}
		},
		"no reason": func(r *projection.NativeCheckResult) { r.Reason = "" },
	} {
		t.Run(name, func(t *testing.T) {
			result := valid
			mutate(&result)
			if _, err := projection.Project([]byte(emiliaORRequirement), projection.Options{
				RoleMap:            identityRoles("a", "b"),
				Facts:              []semantics.EvidenceFact{},
				NativeCheckResults: []projection.NativeCheckResult{result},
			}); err == nil {
				t.Fatalf("malformed native check result was accepted: %+v", result)
			}
		})
	}
}

const statusBothRequirement = `{
  "@version": "EP-AEC-REQUIREMENT-v1",
  "requirement_id": "status-both@1",
  "expression": "a OR b",
  "status_required": ["a", "b"]
}`

// Every required status check needs an explicit result: four outcomes, all
// distinct, each accepted as a report record.
func TestProjectNativeCheckOutcomesAreClosed(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	for _, outcome := range []projection.NativeCheckOutcome{
		projection.NativeCheckSuccess,
		projection.NativeCheckFailed,
		projection.NativeCheckUnavailable,
		projection.NativeCheckNotApplicable,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			rep, err := projection.Project([]byte(statusBothRequirement), projection.Options{
				Now:     now,
				RoleMap: identityRoles("a", "b"),
				Facts:   []semantics.EvidenceFact{},
				NativeCheckResults: []projection.NativeCheckResult{
					nativeResult("status_required:a", "a", outcome, now),
					nativeResult("status_required:b", "b", outcome, now),
				},
			})
			if err != nil {
				t.Fatalf("outcome %q rejected: %v", outcome, err)
			}
			if !rep.NativeChecksComplete {
				t.Fatalf("explicit %q results did not complete the report: %+v", outcome, rep.NativeCheckResults)
			}
			if len(rep.NativeCheckResults) != 2 {
				t.Fatalf("results = %+v, want both components", rep.NativeCheckResults)
			}
		})
	}

	for _, bad := range []projection.NativeCheckOutcome{"", "ok", "SUCCESS", "passed"} {
		if _, err := projection.Project([]byte(statusBothRequirement), projection.Options{
			Now:     now,
			RoleMap: identityRoles("a", "b"),
			Facts:   []semantics.EvidenceFact{},
			NativeCheckResults: []projection.NativeCheckResult{
				{CheckID: "status_required:a", ComponentType: "a", Outcome: bad},
			},
		}); err == nil {
			t.Fatalf("unknown outcome %q was accepted", bad)
		}
	}
}

// Attribution is not optional for an outcome that claims a check ran.
func TestProjectNativeCheckRequiresAttribution(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	complete := nativeResult("status_required:a", "a", projection.NativeCheckSuccess, now)
	cases := map[string]func(*projection.NativeCheckResult){
		"no check id":            func(r *projection.NativeCheckResult) { r.CheckID = "" },
		"no component":           func(r *projection.NativeCheckResult) { r.ComponentType = "" },
		"no evidence digest":     func(r *projection.NativeCheckResult) { r.EvidenceDigest = "" },
		"no verifier":            func(r *projection.NativeCheckResult) { r.Verifier = "" },
		"no profile digest":      func(r *projection.NativeCheckResult) { r.VerifierProfileDigest = "" },
		"no trust snapshot":      func(r *projection.NativeCheckResult) { r.TrustSnapshotDigest = "" },
		"no status snapshot":     func(r *projection.NativeCheckResult) { r.StatusSnapshotDigest = "" },
		"no verification time":   func(r *projection.NativeCheckResult) { r.VerificationTime = time.Time{} },
		"no freshness decision":  func(r *projection.NativeCheckResult) { r.FreshnessDecision = nil },
		"failure without reason": func(r *projection.NativeCheckResult) { r.Outcome = projection.NativeCheckFailed },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			result := complete
			mutate(&result)
			if _, err := projection.Project([]byte(statusBothRequirement), projection.Options{
				Now:                now,
				RoleMap:            identityRoles("a", "b"),
				Facts:              []semantics.EvidenceFact{},
				NativeCheckResults: []projection.NativeCheckResult{result},
			}); err == nil {
				t.Fatalf("malformed native check result was accepted: %+v", result)
			}
		})
	}
}

// An unavailable or not-applicable decision may occur before a status snapshot
// exists.  It still identifies the artifact, verifier and time, but the report
// must not require fabricated snapshot or freshness fields.
func TestProjectNativeCheckWithoutStatusSnapshot(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	for _, outcome := range []projection.NativeCheckOutcome{
		projection.NativeCheckUnavailable,
		projection.NativeCheckNotApplicable,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			first := nativeResult("status_required:a", "a", outcome, now)
			second := nativeResult("status_required:b", "b", outcome, now)
			for _, result := range []*projection.NativeCheckResult{&first, &second} {
				result.TrustSnapshotDigest = ""
				result.StatusSnapshotDigest = ""
				result.FreshnessDecision = nil
			}
			rep, err := projection.Project([]byte(statusBothRequirement), projection.Options{
				Now:                now,
				RoleMap:            identityRoles("a", "b"),
				Facts:              []semantics.EvidenceFact{},
				NativeCheckResults: []projection.NativeCheckResult{first, second},
			})
			if err != nil {
				t.Fatalf("outcome %q without a status snapshot was rejected: %v", outcome, err)
			}
			if !rep.NativeChecksComplete {
				t.Fatal("results without a status snapshot did not complete the report")
			}
		})
	}
}

// Two records for the same component of the same check are contradictory, not
// an extra vote.
func TestProjectNativeCheckRejectsDuplicateComponent(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	first := nativeResult("status_required:a", "a", projection.NativeCheckSuccess, now)
	second := nativeResult("status_required:a", "a", projection.NativeCheckFailed, now)
	if _, err := projection.Project([]byte(statusBothRequirement), projection.Options{
		Now:                now,
		RoleMap:            identityRoles("a", "b"),
		Facts:              []semantics.EvidenceFact{},
		NativeCheckResults: []projection.NativeCheckResult{first, second},
	}); err == nil {
		t.Fatal("two outcomes for one component were accepted")
	}
}

// Completeness is per required check and per component; a result for another
// component does not stand in for the missing one.
func TestProjectNativeChecksCompleteRequiresEveryRequiredCheck(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	project := func(results ...projection.NativeCheckResult) *projection.Report {
		t.Helper()
		rep, err := projection.Project([]byte(statusBothRequirement), projection.Options{
			Now:                now,
			RoleMap:            identityRoles("a", "b"),
			Facts:              []semantics.EvidenceFact{},
			NativeCheckResults: results,
		})
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}

	if rep := project(nativeResult("status_required:a", "a", projection.NativeCheckSuccess, now)); rep.NativeChecksComplete {
		t.Fatal("missing b result still marked native checks complete")
	}
	if rep := project(
		nativeResult("status_required:a", "a", projection.NativeCheckSuccess, now),
		nativeResult("status_required:b", "b", projection.NativeCheckSuccess, now),
	); !rep.NativeChecksComplete {
		t.Fatal("explicit results for every required check were not complete")
	}
}

// A cached status snapshot is acceptable when the record states the profile's
// freshness decision; CLC neither fetches nor refreshes status.
func TestProjectAcceptsCachedStatusSnapshotWithFreshnessDecision(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	result := nativeResult("status_required:a", "a", projection.NativeCheckSuccess, now)
	checkedAt := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	validUntil := checkedAt.Add(time.Minute)
	result.FreshnessDecision = &projection.FreshnessDecision{
		Verdict:    projection.FreshnessCached,
		CheckedAt:  &checkedAt,
		ValidUntil: &validUntil,
	}
	result.ReplayDigest = projection.Digest("sha-256:" + strings.Repeat("e", 64))
	rep, err := projection.Project([]byte(statusBothRequirement), projection.Options{
		Now:     now,
		RoleMap: identityRoles("a", "b"),
		Facts:   []semantics.EvidenceFact{verifiedFact("a", "alice", now), verifiedFact("b", "bob", now)},
		NativeCheckResults: []projection.NativeCheckResult{
			result,
			nativeResult("status_required:b", "b", projection.NativeCheckSuccess, now),
		},
	})
	if err != nil {
		t.Fatalf("cached snapshot with a freshness decision was rejected: %v", err)
	}
	if !rep.NativeChecksComplete {
		t.Fatal("cached-but-attributed results did not complete the report")
	}
	if got := rep.Satisfaction.Satisfaction().Verdict; got != semantics.SatisfactionSatisfied {
		t.Fatalf("verdict = %s, want SATISFIED", got)
	}
	if rep.NativeCheckResults[0].FreshnessDecision == nil ||
		rep.NativeCheckResults[0].ReplayDigest == "" {
		t.Fatalf("freshness/replay attribution was dropped: %+v", rep.NativeCheckResults[0])
	}
}

// A verified revoked status is a failed check, never an unavailable one, and it
// does not poison the sibling OR branch.
func TestProjectRevokedStatusIsFailedNotUnavailable(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	revoked := nativeResult("status_required:a", "a", projection.NativeCheckFailed, now)
	revoked.Reason = "emilia:revoked"
	rep, err := projection.Project([]byte(statusBothRequirement), projection.Options{
		Now:     now,
		RoleMap: identityRoles("a", "b"),
		Facts:   []semantics.EvidenceFact{verifiedFact("b", "bob", now)},
		NativeCheckResults: []projection.NativeCheckResult{
			revoked,
			nativeResult("status_required:b", "b", projection.NativeCheckSuccess, now),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Satisfaction.Satisfaction().Verdict; got != semantics.SatisfactionSatisfied {
		t.Fatalf("verdict = %s, want SATISFIED through the b branch", got)
	}
	var failed, unavailable int
	for _, result := range rep.NativeCheckResults {
		switch result.Outcome {
		case projection.NativeCheckFailed:
			failed++
			if result.Reason != "emilia:revoked" {
				t.Fatalf("revoked reason = %q", result.Reason)
			}
		case projection.NativeCheckUnavailable:
			unavailable++
		}
	}
	if failed != 1 || unavailable != 0 {
		t.Fatalf("revoked status recorded as failed=%d unavailable=%d", failed, unavailable)
	}
	if !rep.NativeChecksComplete {
		t.Fatal("an explicit failed result should complete the report")
	}
}

// When a required check has no result, the evidence-side verdict is still
// reportable, but the report must not claim final native validation.
func TestProjectIncompleteNativeChecksKeepSatisfactionReportable(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	doc := `{
	  "@version": "EP-AEC-REQUIREMENT-v1",
	  "requirement_id": "status-missing@1",
	  "expression": "a",
	  "status_required": ["a"]
	}`
	rep, err := projection.Project([]byte(doc), projection.Options{
		Now:     now,
		RoleMap: identityRoles("a"),
		Facts:   []semantics.EvidenceFact{verifiedFact("a", "alice", now)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Satisfaction.Satisfaction().Verdict; got != semantics.SatisfactionSatisfied {
		t.Fatalf("verdict = %s, want SATISFIED over eligible facts", got)
	}
	if rep.NativeChecksComplete {
		t.Fatal("missing status result marked native checks complete")
	}
	raw := projectJSON(t, rep)
	if !strings.Contains(raw, `"nativeChecksComplete":false`) {
		t.Fatalf("report does not expose incompleteness: %s", raw)
	}
}

// A profile that explicitly establishes non-applicability records it as an
// outcome; it is neither a success nor an unavailability.
func TestProjectNativeCheckNotApplicableIsExplicit(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	doc := `{
	  "@version": "EP-AEC-REQUIREMENT-v1",
	  "requirement_id": "status-na@1",
	  "expression": "a",
	  "status_required": ["a"]
	}`
	rep, err := projection.Project([]byte(doc), projection.Options{
		Now:     now,
		RoleMap: identityRoles("a"),
		Facts:   []semantics.EvidenceFact{},
		NativeCheckResults: []projection.NativeCheckResult{
			nativeResult("status_required:a", "a", projection.NativeCheckNotApplicable, now),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.NativeChecksComplete {
		t.Fatal("explicit not-applicable result did not complete the report")
	}
	if len(rep.NativeCheckResults) != 1 ||
		rep.NativeCheckResults[0].Outcome != projection.NativeCheckNotApplicable {
		t.Fatalf("not-applicable outcome was not preserved: %+v", rep.NativeCheckResults)
	}
	if got := rep.Satisfaction.Satisfaction().Verdict; got != semantics.SatisfactionUnsatisfied {
		t.Fatalf("verdict = %s, want UNSATISFIED with no eligible fact", got)
	}
	if strings.Contains(projectJSON(t, rep), "allow_unresolved") {
		t.Fatal("not-applicable leaked the authorization-only allow_unresolved verdict")
	}
}

// A status check names a component type, so an unpinned one is a refusal.
func TestProjectAECRejectsUnpinnedStatusRole(t *testing.T) {
	req := strings.Replace(emiliaRequirement,
		`"status_required": ["ep-quorum"]`, `"status_required": ["unpinned"]`, 1)
	if _, err := projection.Project([]byte(req), projection.Options{
		Now:     time.Now(),
		RoleMap: emiliaRoleMap(),
	}); err == nil {
		t.Fatal("unpinned status_required role accepted")
	}
}
