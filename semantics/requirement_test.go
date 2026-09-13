// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func wireRequirement() Requirement {
	return Requirement{
		Version:     RequirementVersion,
		ID:          "wire-release-evidence@7",
		Purpose:     "pre-execution evidence check",
		Expression:  "human-authorization AND policy-permit",
		Constraints: []RequirementConstraint{{Role: "human-authorization", Constraint: "varwof/evidence-v1:quorum:distinct:2"}},
	}
}

func evFact(role, subject string, verified bool) EvidenceFact {
	return EvidenceFact{Type: role, Subject: subject, IssuedAt: time.Now().UTC().Add(-time.Second).Truncate(time.Second), Verified: verified}
}

func TestRequirementValidateAndParse(t *testing.T) {
	req := wireRequirement()
	if err := req.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	roles, err := req.Roles()
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if strings.Join(roles, ",") != "human-authorization,policy-permit" {
		t.Fatalf("roles = %v", roles)
	}

	raw := []byte(`{"@version":"CLC-REQUIREMENT-v1","requirement_id":"r@1","expression":"a"}`)
	if _, err := ParseRequirement(raw); err != nil {
		t.Fatalf("ParseRequirement: %v", err)
	}

	// Closed object: an undefined member is an error, not something to ignore.
	unknownMember := []byte(`{"@version":"CLC-REQUIREMENT-v1","requirement_id":"r@1","expression":"a","advice":"please"}`)
	if _, err := ParseRequirement(unknownMember); !errors.Is(err, ErrRequirementShape) {
		t.Errorf("unknown member: got %v, want ErrRequirementShape", err)
	}

	badVersion := req
	badVersion.Version = "CLС-REQUIREMENT-v2"
	if err := badVersion.Validate(); !errors.Is(err, ErrRequirementVersion) {
		t.Errorf("version: got %v, want ErrRequirementVersion", err)
	}

	noID := req
	noID.ID = ""
	if err := noID.Validate(); !errors.Is(err, ErrRequirementShape) {
		t.Errorf("missing id: got %v, want ErrRequirementShape", err)
	}

	badConstraint := req
	badConstraint.Constraints = []RequirementConstraint{{Role: "human-authorization", Constraint: "varwof/evidence-v1:quorum:distinct:1"}}
	if err := badConstraint.Validate(); !errors.Is(err, ErrEvidenceConstraint) {
		t.Errorf("bad constraint: got %v, want ErrEvidenceConstraint", err)
	}

	// Role-less constraints are refused: the core must not guess the role.
	roleLess := req
	roleLess.Constraints = []RequirementConstraint{{Constraint: "varwof/evidence-v1:consumption:once"}}
	if err := roleLess.Validate(); !errors.Is(err, ErrRequirementShape) {
		t.Errorf("role-less constraint: got %v, want ErrRequirementShape", err)
	}
}

// deepRequirementExpression nests parentheses to depth levels, to exercise the
// bounded parser.
func deepRequirementExpression(depth int) string {
	return strings.Repeat("(", depth) + "a" + strings.Repeat(" OR a)", depth)
}

func TestRequirementExpressionGrammar(t *testing.T) {
	good := []string{
		"a",
		"a AND b",
		"a AND b OR c",
		"(a OR b) AND c",
		"a && b || c",
		"  a   AND\t(b OR c)  ",
		"human-authorization AND policy-permit",
		"ns.role:1_x AND b-2",
	}
	for _, expr := range good {
		req := Requirement{Version: RequirementVersion, ID: "r@1", Expression: expr}
		if err := req.Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", expr, err)
		}
	}

	bad := []string{
		"",
		"AND b",
		"a AND",
		"a b",
		"(a",
		"a)",
		"()",
		"a NOT b",
		"a + b",
		deepRequirementExpression(maxRequirementDepth + 3),    // nesting beyond the limit
		strings.Repeat("a AND ", maxRequirementNodes+5) + "a", // more terms than the limit
		"a &&& b", // malformed symbolic operator
		"a | b",   // single pipe is not an operator
	}
	for _, expr := range bad {
		req := Requirement{Version: RequirementVersion, ID: "r@1", Expression: expr}
		if err := req.Validate(); err == nil {
			t.Errorf("Validate(%q) = nil, want an error", expr)
		}
	}
}

// AEC §8: AND and OR have equal binding strength and associate strictly left to
// right; parentheses are the only precedence mechanism.
func TestRequirementExpressionIsLeftToRight(t *testing.T) {
	// a OR b AND c must mean (a OR b) AND c, so with only a present it is false.
	req := Requirement{Version: RequirementVersion, ID: "r@1", Expression: "a OR b AND c"}
	facts := []EvidenceFact{evFact("a", "s1", true)}
	got, err := EvaluateRequirement(req, facts, EvidenceContext{Now: time.Now().UTC()})
	if err != nil {
		t.Fatalf("EvaluateRequirement: %v", err)
	}
	if got.Expression {
		t.Error("a OR b AND c with only a must be false under left-to-right binding")
	}
	// Parenthesised, the same names admit.
	req.Expression = "a OR (b AND c)"
	got, err = EvaluateRequirement(req, facts, EvidenceContext{Now: time.Now().UTC()})
	if err != nil {
		t.Fatalf("EvaluateRequirement: %v", err)
	}
	if !got.Expression {
		t.Error("a OR (b AND c) with a present must be true")
	}
}

func TestEvaluateRequirement(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	ctx := EvidenceContext{Now: base}
	twoApprovers := []EvidenceFact{
		evFact("human-authorization", "alice", true),
		evFact("human-authorization", "bob", true),
		evFact("policy-permit", "policy-1", true),
	}

	req := wireRequirement()
	got, err := EvaluateRequirement(req, twoApprovers, ctx)
	if err != nil {
		t.Fatalf("EvaluateRequirement: %v", err)
	}
	if got.Verdict != EvidenceSatisfied || !got.Satisfied() {
		t.Fatalf("full evidence: %+v, want satisfied", got)
	}
	if got.Digest.Alg == "" || len(got.Digest.Value) == 0 {
		t.Error("result carries no requirement digest")
	}

	// One approver is not a quorum.
	oneApprover := []EvidenceFact{evFact("human-authorization", "alice", true), evFact("policy-permit", "policy-1", true)}
	got, err = EvaluateRequirement(req, oneApprover, ctx)
	if err != nil {
		t.Fatalf("EvaluateRequirement: %v", err)
	}
	if got.Verdict != EvidenceViolated {
		t.Fatalf("one approver: %+v, want violated", got)
	}

	// A missing role makes the expression false and the outcome a refusal.
	noPermit := []EvidenceFact{evFact("human-authorization", "alice", true), evFact("human-authorization", "bob", true)}
	got, err = EvaluateRequirement(req, noPermit, ctx)
	if err != nil {
		t.Fatalf("EvaluateRequirement: %v", err)
	}
	if got.Verdict != EvidenceViolated || got.Expression {
		t.Fatalf("missing role: %+v, want violated with a false expression", got)
	}
	if len(got.MissingRoles) != 1 || got.MissingRoles[0] != "policy-permit" {
		t.Fatalf("missing roles = %v, want [policy-permit]", got.MissingRoles)
	}

	// An unverified fact fills no role.
	unverified := []EvidenceFact{
		evFact("human-authorization", "alice", true),
		evFact("human-authorization", "bob", false),
		evFact("policy-permit", "policy-1", true),
	}
	got, err = EvaluateRequirement(req, unverified, ctx)
	if err != nil {
		t.Fatalf("EvaluateRequirement: %v", err)
	}
	if got.Verdict != EvidenceViolated {
		t.Fatalf("unverified approver: %+v, want violated", got)
	}
}

// A constraint the core cannot decide leaves the outcome unknown, not satisfied
// and not silently dropped.
func TestEvaluateRequirementUnknownIsFailClosed(t *testing.T) {
	req := wireRequirement()
	req.Expression = "human-authorization"
	req.Constraints = []RequirementConstraint{
		{Role: "human-authorization", Constraint: "varwof/evidence-v1:consumption:once"},
	}
	facts := []EvidenceFact{evFact("human-authorization", "alice", true)}

	got, err := EvaluateRequirement(req, facts, EvidenceContext{Now: time.Now().UTC()})
	if err != nil {
		t.Fatalf("EvaluateRequirement: %v", err)
	}
	if got.Verdict != EvidenceUnknown || got.Satisfied() {
		t.Fatalf("consumption: %+v, want unknown and not satisfied", got)
	}
}

// The requirement is part of the hashed record inputs, so a record shows which
// bar was applied — and the bar itself is never taken from the evidence.
func TestRecordBindsRequirementDigest(t *testing.T) {
	req := wireRequirement()
	grant := Grant{ID: "std/database-v1:query:SELECT"}
	op := Operation{ID: "std/database-v1:query:SELECT"}

	plain, err := Record([]Grant{grant}, op)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	withReq, err := RecordWith([]Grant{grant}, op, RecordOptions{Requirement: &req})
	if err != nil {
		t.Fatalf("RecordWith: %v", err)
	}
	if err := withReq.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if withReq.Inputs.RequirementDigest == nil {
		t.Fatal("requirement digest missing from the record")
	}
	want, err := req.Digest()
	if err != nil {
		t.Fatalf("Requirement.Digest: %v", err)
	}
	if !withReq.Inputs.RequirementDigest.Equal(want) {
		t.Error("recorded requirement digest does not match the requirement")
	}
	if plain.InputDigest.Equal(withReq.InputDigest) {
		t.Error("the requirement must change the input digest")
	}
	if plain.Inputs.RequirementDigest != nil {
		t.Error("a record without a requirement must not carry one")
	}

	// A malformed requirement is refused before anything is recorded.
	bad := req
	bad.Constraints = []RequirementConstraint{{Role: "human-authorization", Constraint: "nonsense"}}
	if _, err := RecordWith([]Grant{grant}, op, RecordOptions{Requirement: &bad}); !errors.Is(err, ErrEvidenceConstraint) {
		t.Errorf("malformed requirement: got %v, want ErrEvidenceConstraint", err)
	}
}
