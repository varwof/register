// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection_test

import (
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
