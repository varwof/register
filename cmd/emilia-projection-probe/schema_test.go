// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package main

import (
	"strings"
	"testing"
)

// TestSchemaCarrierFailsClosed pins the refusal side of the schema-bearing
// fixture. Every uncertain input must be an error; none of these cases may
// reach an accept.
func TestSchemaCarrierFailsClosed(t *testing.T) {
	f := loadSchemaBindingFixture()
	if err := schemaCarrierError(f, cloneBinding(f.Binding), cloneResults(f.NativeStatusResults)); err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*schemaBindingDocument)
	}{
		{"missing schema document", func(d *schemaBindingDocument) { d.StatusSchemaDocument = nil }},
		{"empty accepted pin set", func(d *schemaBindingDocument) { d.AcceptedStatusSchemaDigests = nil }},
		{"empty target id", func(d *schemaBindingDocument) { d.Binding.Targets[0]["artifact_id"] = "" }},
		{"duplicate target id", func(d *schemaBindingDocument) {
			d.Binding.Targets[1]["artifact_id"] = d.Binding.Targets[0]["artifact_id"]
		}},
		{"empty target set", func(d *schemaBindingDocument) { d.Binding.Targets = nil }},
		{"target type differs from schema", func(d *schemaBindingDocument) {
			d.Binding.Targets[0]["type"] = "policy-permit"
		}},
		{"schema id does not name the document", func(d *schemaBindingDocument) {
			d.Binding.Targets[0]["status_schema"].(map[string]any)["id"] = "https://example.org/other.json"
		}},
		{"unpinned schema digest", func(d *schemaBindingDocument) {
			d.Binding.Targets[0]["status_schema"].(map[string]any)["digest"] = "sha-256:" + strings.Repeat("0", 64)
		}},
	}
	for _, tc := range cases {
		d := loadSchemaBindingFixture()
		d.Binding = cloneBinding(f.Binding)
		d.NativeStatusResults = cloneResults(f.NativeStatusResults)
		tc.mutate(&d)
		if err := schemaCarrierError(d, d.Binding, d.NativeStatusResults); err == nil {
			t.Fatalf("%s: accepted", tc.name)
		}
	}

	// Result-side failures: a result without a carrier, a result missing its
	// id, and a result whose schema differs from the carrier.
	for _, tc := range []struct {
		name   string
		mutate func(*schemaResult)
	}{
		{"result has no carrier", func(r *schemaResult) { r.ArtifactID = "" }},
		{"result names an omitted carrier", func(r *schemaResult) { r.ArtifactID = "approval-carol" }},
		{"result schema differs from carrier", func(r *schemaResult) {
			r.StatusSchema["id"] = "https://example.org/other.json"
		}},
		{"result has no schema", func(r *schemaResult) { r.StatusSchema = nil }},
	} {
		results := cloneResults(f.NativeStatusResults)
		tc.mutate(&results[0])
		if err := schemaCarrierError(f, cloneBinding(f.Binding), results); err == nil {
			t.Fatalf("%s: accepted", tc.name)
		}
	}
}

func TestRelianceFailsClosed(t *testing.T) {
	if got := relianceAccepts("SATISFIED", true, []string{"success"}); got != "accept" {
		t.Fatalf("complete success = %q", got)
	}
	for _, tc := range []struct {
		name         string
		satisfaction string
		complete     bool
		outcomes     []string
	}{
		{"empty outcome set", "SATISFIED", true, nil},
		{"satisfied but incomplete", "SATISFIED", false, []string{"success"}},
		{"complete but failed", "SATISFIED", true, []string{"failed"}},
		{"unknown outcome", "SATISFIED", true, []string{"unknown"}},
		{"missing outcome", "SATISFIED", true, []string{""}},
	} {
		if got := relianceAccepts(tc.satisfaction, tc.complete, tc.outcomes); got != "reject" {
			t.Fatalf("%s: %q", tc.name, got)
		}
	}
}

// TestCompletenessCasesExerciseTheirNamedCondition guards the fixture rather
// than the rule. A case whose inputs already fail an earlier check passes for
// the wrong reason and prints the same want/got line either way, so only the
// fixture bytes show the difference. EMI-COMP-002 shipped with satisfaction
// UNSATISFIED, which masked the required-outcome check entirely.
func TestCompletenessCasesExerciseTheirNamedCondition(t *testing.T) {
	want := map[string]struct {
		satisfaction  string
		complete      bool
		failedOutcome bool
	}{
		"EMI-COMP-001": {"SATISFIED", false, false},
		"EMI-COMP-002": {"SATISFIED", true, true},
		"EMI-COMP-003": {"SATISFIED", true, false},
	}
	cases := loadSchemaBindingFixture().CompletenessCases
	if len(cases) != len(want) {
		t.Fatalf("fixture carries %d completeness cases, want %d", len(cases), len(want))
	}
	for _, c := range cases {
		w, ok := want[c.ID]
		if !ok {
			t.Fatalf("unexpected completeness case %q", c.ID)
		}
		if c.Satisfaction != w.satisfaction || c.Complete != w.complete {
			t.Fatalf("%s: satisfaction=%q complete=%v, want %q/%v",
				c.ID, c.Satisfaction, c.Complete, w.satisfaction, w.complete)
		}
		failedOutcome := false
		for _, outcome := range c.RequiredOutcomes {
			if outcome != "success" {
				failedOutcome = true
			}
		}
		if failedOutcome != w.failedOutcome {
			t.Fatalf("%s: failed required outcome = %v, want %v", c.ID, failedOutcome, w.failedOutcome)
		}
	}
}
