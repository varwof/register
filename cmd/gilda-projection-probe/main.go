// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command gilda-projection-probe projects an audit record from
// draft-gilda-wimse-agent-audit-record-02 onto the CLC result vocabulary.
//
// The AEC probe tested the Requirement side (an evidence requirement projected
// into CLC-REQUIREMENT-v1).  This one tests the Result side: a record that
// carries a decision, an evaluation status and a derived agreement, and the
// question is which CLC verdict it may honestly be read as — and which of its
// members have no CLC axis at all.
//
// Field values checked against draft-gilda-wimse-agent-audit-record-02 on
// 2026-10-17: §5.3 (decision.reported, agreement), §6.5 (a decision that was
// not evaluated, unavailableInput).  The draft was later renamed to
// draft-gilda-audit-agent-audit-record; the current -00 keeps §5.4 Evaluation
// with the same members, so the spec cites the new name while this probe's
// checkpoint is the -02 revision above.
package main

import "fmt"

// record is the subset of the Gilda record this probe projects.
type record struct {
	ID          string
	Reported    string   // permit | permit-with-conditions | deny
	Status      string   // evaluated | not-evaluated
	Unavailable []string // unavailableInput, present when not-evaluated
	Observed    string   // effect.observed, e.g. "occurred"
	Agreement   string   // agree | disagree | not-exercised | indeterminate | one-sided
}

// project maps the record onto the CLC result vocabulary and returns what could
// not be carried.
func project(r record) (string, []string) {
	var residual []string
	var verdict string

	if r.Status == "not-evaluated" {
		// §6.5: a permit recorded as not-evaluated is a decision point failing
		// open.  It cannot be read as CLC `allow`; the missing inputs travel as
		// residual obligations instead.
		for _, u := range r.Unavailable {
			residual = append(residual, "unavailableInput:"+u)
		}
		if r.Reported == "deny" {
			verdict = "deny" // fail-closed
		} else {
			verdict = "allow_unresolved"
		}
	} else {
		switch r.Reported {
		case "permit":
			verdict = "allow"
		case "permit-with-conditions":
			verdict = "allow_unresolved"
			residual = append(residual, "conditions: carrier-owned")
		case "deny":
			verdict = "deny"
		default:
			verdict = "unknown"
			residual = append(residual, "decision.reported="+r.Reported+": not mapped")
		}
	}

	// agreement is a relation between the recorded decision and the observed
	// effect.  CLC has no axis for it: a verdict and a relation are different
	// kinds, exactly as with AEC required_bindings.
	if r.Agreement != "" && r.Agreement != "agree" {
		residual = append(residual, "agreement="+r.Agreement+": relation between decision and effect, no CLC axis")
	}
	if r.Observed != "" && r.Observed != "occurred" && r.Agreement == "agree" {
		residual = append(residual, "effect.observed="+r.Observed+": agreement says agree")
	}
	return verdict, residual
}

func main() {
	cases := []struct {
		caseID string
		rec    record
		want   string
	}{
		{"GIL-001", record{"g-1", "permit", "evaluated", nil, "occurred", "agree"}, "allow"},
		{"GIL-002", record{"g-2", "permit-with-conditions", "evaluated", nil, "occurred", "agree"}, "allow_unresolved"},
		{"GIL-003", record{"g-3", "deny", "evaluated", nil, "occurred", "disagree"}, "deny"},
		{"GIL-004", record{"g-4", "permit", "not-evaluated", []string{"standing source"}, "occurred", "indeterminate"}, "allow_unresolved"},
		{"GIL-005", record{"g-5", "deny", "not-evaluated", []string{"consumption state"}, "occurred", "indeterminate"}, "deny"},
		{"GIL-006", record{"g-6", "permit", "evaluated", nil, "not-observed", "one-sided"}, "allow"},
	}

	fmt.Println("Gilda audit record → CLC result vocabulary")
	fmt.Println("Fields: draft-gilda-wimse-agent-audit-record-02 §5.3, §6.5 (checked 2026-10-17)")
	fmt.Println()
	for _, c := range cases {
		got, residual := project(c.rec)
		status := "PASS"
		if got != c.want {
			status = "FAIL"
		}
		fmt.Printf("%s %s  record=%s reported=%-22s status=%-13s observed=%-12s agreement=%-13s want=%s got=%s\n",
			status, c.caseID, c.rec.ID, c.rec.Reported, c.rec.Status, c.rec.Observed, c.rec.Agreement, c.want, got)
		for _, r := range residual {
			fmt.Println("      residual: " + r)
		}
	}
	fmt.Println()
	fmt.Println("Reading: the decision and evaluation members project cleanly; the derived")
	fmt.Println("agreement does not.  It is the second instance of the same boundary as AEC")
	fmt.Println("required_bindings: a relation between two artifacts is not a CLC verdict.")
}
