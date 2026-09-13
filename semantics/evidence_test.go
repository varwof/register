// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"errors"
	"testing"
	"time"
)

func TestValidateEvidenceConstraint(t *testing.T) {
	good := []string{
		"varwof/evidence-v1:freshness:sec:300",
		"varwof/evidence-v1:freshness:sec:0",
		"varwof/evidence-v1:consumption:once",
		"varwof/evidence-v1:quorum:distinct:2",
		"varwof/evidence-v1:exclusion:initiator",
		"varwof/evidence-v1:exclusion:executor",
	}
	for _, c := range good {
		if err := ValidateEvidenceConstraint(c); err != nil {
			t.Errorf("ValidateEvidenceConstraint(%q) = %v, want nil", c, err)
		}
	}

	bad := []string{
		"",
		"varwof/evidence-v1:freshness",          // missing value
		"varwof/evidence-v1:freshness:sec",      // missing bound
		"varwof/evidence-v1:freshness:min:5",    // wrong unit
		"varwof/evidence-v1:freshness:sec:-1",   // negative
		"varwof/evidence-v1:freshness:sec:many", // not a number
		"varwof/evidence-v1:consumption",        // missing mode
		"varwof/evidence-v1:consumption:twice",  // unsupported mode
		"varwof/evidence-v1:quorum:distinct:1",  // a quorum is > 1
		"varwof/evidence-v1:quorum:distinct:0",  // not a quorum
		"varwof/evidence-v1:quorum:same:2",      // unclosed mode
		"varwof/evidence-v1:exclusion:approver", // unsupported identity
		"varwof/evidence-v1:exclusion",          // missing identity
		"varwof/evidence-v1:role:2",             // unknown type
		"varwof/constraint-v1:max_rows:100",     // authorization-side pair
		"other/scheme-v1:freshness:sec:60",      // wrong declaring scheme
	}
	for _, c := range bad {
		if err := ValidateEvidenceConstraint(c); !errors.Is(err, ErrEvidenceConstraint) {
			t.Errorf("ValidateEvidenceConstraint(%q) = %v, want ErrEvidenceConstraint", c, err)
		}
	}
}

// factAt builds a fact relative to an explicit appraisal instant, so a bound of
// exactly N seconds is testable without racing the clock.
func factAt(base time.Time, subject string, age time.Duration, verified bool) EvidenceFact {
	return EvidenceFact{
		Type:     "human-authorization",
		Subject:  subject,
		IssuedAt: base.Add(-age).Truncate(time.Second),
		Verified: verified,
	}
}

func TestEvaluateEvidenceFreshness(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	cases := []struct {
		name   string
		facts  []EvidenceFact
		want   EvidenceVerdict
		reason string
	}{
		{"inside bound", []EvidenceFact{factAt(base, "alice", 30*time.Second, true)}, EvidenceSatisfied, ""},
		{"exactly at bound", []EvidenceFact{factAt(base, "alice", 60*time.Second, true)}, EvidenceSatisfied, ""},
		{"stale", []EvidenceFact{factAt(base, "alice", 90*time.Second, true)}, EvidenceViolated, "freshness:stale"},
		{
			"future issued",
			[]EvidenceFact{{Type: "human-authorization", Subject: "alice", IssuedAt: base.Add(time.Minute), Verified: true}},
			EvidenceViolated, "freshness:future_issued",
		},
		{
			"missing issuance time",
			[]EvidenceFact{{Type: "human-authorization", Subject: "alice", Verified: true}},
			EvidenceViolated, "freshness:no_issuance_time",
		},
		{"unverified does not count", []EvidenceFact{factAt(base, "alice", 10*time.Second, false)}, EvidenceViolated, "freshness:no_eligible_fact"},
		{"no facts at all", nil, EvidenceViolated, "freshness:no_eligible_fact"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EvaluateEvidenceConstraint("varwof/evidence-v1:freshness:sec:60", tc.facts, EvidenceContext{Now: base})
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got.Verdict != tc.want || got.Reason != tc.reason {
				t.Fatalf("got %s/%q, want %s/%q", got.Verdict, got.Reason, tc.want, tc.reason)
			}
		})
	}
}

func TestEvaluateEvidenceQuorum(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	ctx := EvidenceContext{Now: base}

	two := []EvidenceFact{factAt(base, "alice", time.Second, true), factAt(base, "bob", time.Second, true)}
	if got, err := EvaluateEvidenceConstraint("varwof/evidence-v1:quorum:distinct:2", two, ctx); err != nil || got.Verdict != EvidenceSatisfied {
		t.Fatalf("two distinct approvers: %+v (%v), want satisfied", got, err)
	}

	// The same approver twice is one approver.
	repeated := []EvidenceFact{factAt(base, "alice", time.Second, true), factAt(base, "alice", 2*time.Second, true)}
	if got, err := EvaluateEvidenceConstraint("varwof/evidence-v1:quorum:distinct:2", repeated, ctx); err != nil || got.Verdict != EvidenceViolated {
		t.Fatalf("repeated approver: %+v (%v), want violated", got, err)
	}

	// An unverified fact cannot fill a seat.
	unverified := []EvidenceFact{factAt(base, "alice", time.Second, true), factAt(base, "bob", time.Second, false)}
	if got, _ := EvaluateEvidenceConstraint("varwof/evidence-v1:quorum:distinct:2", unverified, ctx); got.Verdict != EvidenceViolated {
		t.Fatalf("unverified approver counted: %+v", got)
	}

	// A fact with no verified subject identifier cannot be counted either.
	anonymous := []EvidenceFact{factAt(base, "alice", time.Second, true), factAt(base, "", time.Second, true)}
	if got, _ := EvaluateEvidenceConstraint("varwof/evidence-v1:quorum:distinct:2", anonymous, ctx); got.Verdict != EvidenceViolated {
		t.Fatalf("anonymous fact counted: %+v", got)
	}

	three := append(two, factAt(base, "carol", time.Second, true))
	if got, _ := EvaluateEvidenceConstraint("varwof/evidence-v1:quorum:distinct:3", three, ctx); got.Verdict != EvidenceSatisfied {
		t.Fatalf("three distinct approvers: %+v", got)
	}
}

func TestEvaluateEvidenceExclusion(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	approvers := []EvidenceFact{factAt(now, "alice", time.Second, true), factAt(now, "bob", time.Second, true)}

	ok := EvidenceContext{Now: now, Initiator: "carol", Executor: "dave"}
	if got, err := EvaluateEvidenceConstraint("varwof/evidence-v1:exclusion:initiator", approvers, ok); err != nil || got.Verdict != EvidenceSatisfied {
		t.Fatalf("initiator not among approvers: %+v (%v), want satisfied", got, err)
	}

	self := EvidenceContext{Now: now, Initiator: "alice", Executor: "dave"}
	if got, err := EvaluateEvidenceConstraint("varwof/evidence-v1:exclusion:initiator", approvers, self); err != nil || got.Verdict != EvidenceViolated {
		t.Fatalf("initiator approved its own action: %+v (%v), want violated", got, err)
	}
	if got, err := EvaluateEvidenceConstraint("varwof/evidence-v1:exclusion:executor", approvers, EvidenceContext{Now: now, Executor: "bob"}); err != nil || got.Verdict != EvidenceViolated {
		t.Fatalf("executor approved its own action: %+v (%v), want violated", got, err)
	}

	// Without the boundary-owned identity, exclusion is established by nobody:
	// absence is unknown, never "not excluded".
	missing := EvidenceContext{Now: now}
	got, err := EvaluateEvidenceConstraint("varwof/evidence-v1:exclusion:initiator", approvers, missing)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Verdict != EvidenceUnknown || got.Reason != "exclusion:identity_not_supplied" {
		t.Fatalf("missing identity: %+v, want unknown", got)
	}
}

// Consumption is recognized but never core-evaluated: durable state belongs to
// the enforcement point, so the core hands back a residual obligation.
func TestEvaluateEvidenceConsumptionIsResidual(t *testing.T) {
	got, err := EvaluateEvidenceConstraint("varwof/evidence-v1:consumption:once", nil, EvidenceContext{Now: time.Now().UTC()})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if got.Verdict != EvidenceUnknown || got.Reason != ErrEvidenceNotCoreEvaluated.Error() {
		t.Fatalf("consumption: %+v, want unknown/%s", got, ErrEvidenceNotCoreEvaluated)
	}
	if CoreEvaluatesEvidenceConstraint("varwof/evidence-v1:consumption:once") {
		t.Error("consumption must not claim a core evaluator")
	}
	for _, c := range []string{
		"varwof/evidence-v1:freshness:sec:60",
		"varwof/evidence-v1:quorum:distinct:2",
		"varwof/evidence-v1:exclusion:executor",
	} {
		if !CoreEvaluatesEvidenceConstraint(c) {
			t.Errorf("%s should have a core evaluator", c)
		}
	}
	if CoreEvaluatesEvidenceConstraint("nonsense") {
		t.Error("unrecognized constraint must not claim a core evaluator")
	}
}

func TestEvaluateEvidenceRejectsMalformed(t *testing.T) {
	if _, err := EvaluateEvidenceConstraint("varwof/evidence-v1:quorum:distinct:1", nil, EvidenceContext{}); !errors.Is(err, ErrEvidenceConstraint) {
		t.Errorf("malformed constraint: got %v, want ErrEvidenceConstraint", err)
	}
}

func TestEvidenceFactsOfRole(t *testing.T) {
	facts := []EvidenceFact{
		{Type: "human-authorization", Subject: "alice", Verified: true},
		{Type: "policy-permit", Subject: "policy", Verified: true},
		{Type: "human-authorization", Subject: "bob", Verified: true},
	}
	got := EvidenceFactsOfRole(facts, "human-authorization")
	if len(got) != 2 {
		t.Fatalf("role filter returned %d facts, want 2", len(got))
	}
	if got, err := EvaluateEvidenceConstraint("varwof/evidence-v1:quorum:distinct:2", EvidenceFactsOfRole(facts, "human-authorization"), EvidenceContext{Now: time.Now().UTC()}); err != nil || got.Verdict != EvidenceSatisfied {
		t.Fatalf("role-scoped quorum: %+v (%v)", got, err)
	}
}
