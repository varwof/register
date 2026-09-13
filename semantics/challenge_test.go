// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"errors"
	"testing"
	"time"
)

func challengeParams(now time.Time) ChallengeParams {
	return ChallengeParams{
		ID:           "ch_01H",
		Nonce:        "nonce-0123456789",
		Audience:     "https://gateway-a.example",
		ActionDigest: dg("the-action"),
		Now:          now,
		TTL:          5 * time.Minute,
	}
}

func TestBuildChallengeFromRequirement(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	req := wireRequirement()

	// Two approvers present, no permit: the expression is false and the missing
	// role is what the challenge must name.
	result, err := EvaluateRequirement(req, []EvidenceFact{
		evFact("human-authorization", "alice", true),
		evFact("human-authorization", "bob", true),
	}, EvidenceContext{Now: base})
	if err != nil {
		t.Fatalf("EvaluateRequirement: %v", err)
	}
	if result.Verdict != EvidenceViolated {
		t.Fatalf("result = %+v, want violated", result)
	}

	c, err := BuildChallengeFromRequirement(req, result, challengeParams(base))
	if err != nil {
		t.Fatalf("BuildChallengeFromRequirement: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.Authorizes() {
		t.Error("a challenge must never authorize")
	}
	if len(c.Required) != 1 || c.Required[0].ID != "policy-permit" || c.Required[0].Reason != "role_unfilled" {
		t.Fatalf("required = %+v, want the unfilled policy-permit role", c.Required)
	}
	if c.RequirementID != req.ID || c.RequirementDigest == nil {
		t.Errorf("challenge is not bound to the requirement: %+v", c)
	}
	if !c.ActionDigest.Equal(dg("the-action")) {
		t.Error("challenge is not bound to the action")
	}
	if !c.ExpiresAt.Equal(base.Add(5 * time.Minute)) {
		t.Errorf("expires_at = %s", c.ExpiresAt)
	}
	if err := c.Usable(base); err != nil {
		t.Errorf("Usable now: %v", err)
	}
	if err := c.Usable(base.Add(6 * time.Minute)); !errors.Is(err, ErrChallengeExpired) {
		t.Errorf("Usable later: got %v, want ErrChallengeExpired", err)
	}

	// A satisfied requirement needs no challenge, and neither does a refusal
	// with nothing outstanding.
	satisfied := result
	satisfied.Verdict = EvidenceSatisfied
	if _, err := BuildChallengeFromRequirement(req, satisfied, challengeParams(base)); !errors.Is(err, ErrChallengeNotOutstanding) {
		t.Errorf("satisfied: got %v, want ErrChallengeNotOutstanding", err)
	}
	empty := RequirementResult{RequirementID: req.ID, Verdict: EvidenceViolated}
	if _, err := BuildChallengeFromRequirement(req, empty, challengeParams(base)); !errors.Is(err, ErrChallengeNotOutstanding) {
		t.Errorf("nothing missing: got %v, want ErrChallengeNotOutstanding", err)
	}
}

// The evidence side's unknown is outstanding too: a constraint the core must not
// answer becomes a required item with its reason.
func TestBuildChallengeFromUnknownConstraint(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	req := wireRequirement()
	req.Expression = "human-authorization"
	req.Constraints = []RequirementConstraint{{Role: "human-authorization", Constraint: "varwof/evidence-v1:consumption:once"}}

	result, err := EvaluateRequirement(req, []EvidenceFact{evFact("human-authorization", "alice", true)}, EvidenceContext{Now: base})
	if err != nil {
		t.Fatalf("EvaluateRequirement: %v", err)
	}
	if result.Verdict != EvidenceUnknown {
		t.Fatalf("result = %+v, want unknown", result)
	}
	c, err := BuildChallengeFromRequirement(req, result, challengeParams(base))
	if err != nil {
		t.Fatalf("BuildChallengeFromRequirement: %v", err)
	}
	if len(c.Required) != 1 || c.Required[0].Constraint != "varwof/evidence-v1:consumption:once" {
		t.Fatalf("required = %+v, want the consumption obligation", c.Required)
	}
	if c.Required[0].Reason != ErrEvidenceNotCoreEvaluated.Error() {
		t.Errorf("reason = %q, want the stable not-core-evaluated code", c.Required[0].Reason)
	}
}

// The authorization side's allow_unresolved produces the same object, naming
// the obligation identities rather than roles.
func TestBuildChallengeFromDecision(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	dec := Authorize(
		Grant{ID: "std/database-v1:query:SELECT", Constraints: []string{windowObligation}},
		Operation{ID: "std/database-v1:query:SELECT"},
	)
	if dec.Verdict != VerdictAllowUR {
		t.Fatalf("verdict = %q, want allow_unresolved", dec.Verdict)
	}
	c, err := BuildChallengeFromDecision(dec, challengeParams(base))
	if err != nil {
		t.Fatalf("BuildChallengeFromDecision: %v", err)
	}
	if len(c.Required) != 1 || c.Required[0].ID != "varwof/constraint-v1:time" {
		t.Fatalf("required = %+v, want the time obligation identity", c.Required)
	}
	if c.Required[0].Constraint != windowObligation {
		t.Errorf("constraint = %q, want the exact obligation text", c.Required[0].Constraint)
	}
	if c.RequirementDigest != nil {
		t.Error("an authorization-side challenge must not claim a requirement digest")
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// A plain allow or deny has nothing to ask for.
	for _, d := range []Decision{
		{Verdict: VerdictAllow},
		{Verdict: VerdictDeny, Reason: "capability_not_authorized"},
	} {
		if _, err := BuildChallengeFromDecision(d, challengeParams(base)); !errors.Is(err, ErrChallengeNotOutstanding) {
			t.Errorf("verdict %s: got %v, want ErrChallengeNotOutstanding", d.Verdict, err)
		}
	}
}

func TestChallengeValidation(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	good, err := BuildChallengeFromDecision(
		Authorize(Grant{ID: "std/database-v1:query:SELECT", Constraints: []string{windowObligation}}, Operation{ID: "std/database-v1:query:SELECT"}),
		challengeParams(base),
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Challenge)
	}{
		{"wrong version", func(c *Challenge) { c.Version = "CLC-CHALLENGE-v2" }},
		{"missing id", func(c *Challenge) { c.ID = "" }},
		{"short nonce", func(c *Challenge) { c.Nonce = "short" }},
		{"oversized nonce", func(c *Challenge) { c.Nonce = string(make([]byte, maxChallengeNonceBytes+1)) }},
		{"no action digest", func(c *Challenge) { c.ActionDigest = Digest{} }},
		{"nothing required", func(c *Challenge) { c.Required = nil }},
		{"item without id", func(c *Challenge) { c.Required = []ChallengeItem{{}} }},
		{"no expiry", func(c *Challenge) { c.ExpiresAt = time.Time{} }},
		{"non-UTC expiry", func(c *Challenge) { c.ExpiresAt = base.In(time.FixedZone("CST", 8*3600)) }},
		{"retry without instant", func(c *Challenge) { c.Retry = &RetryTiming{JitterSec: 5} }},
		{"retry past expiry", func(c *Challenge) {
			c.Retry = &RetryTiming{NotBefore: c.ExpiresAt.Add(time.Hour)}
		}},
		{"jitter out of range", func(c *Challenge) {
			c.Retry = &RetryTiming{NotBefore: base, JitterSec: maxChallengeJitterSec + 1}
		}},
		{"unusable requirement digest", func(c *Challenge) { c.RequirementDigest = &Digest{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := good
			tc.mutate(&bad)
			if err := bad.Validate(); !errors.Is(err, ErrChallengeShape) {
				t.Fatalf("Validate = %v, want ErrChallengeShape", err)
			}
		})
	}
}

// Retry timing gates the retry itself: too early is a stable refusal, so a
// client cannot turn the challenge into a load amplifier.
func TestChallengeRetryTiming(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	params := challengeParams(base)
	params.Retry = &RetryTiming{NotBefore: base.Add(30 * time.Second), JitterSec: 10}

	dec := Authorize(Grant{ID: "std/database-v1:query:SELECT", Constraints: []string{windowObligation}}, Operation{ID: "std/database-v1:query:SELECT"})
	c, err := BuildChallengeFromDecision(dec, params)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := c.Usable(base); !errors.Is(err, ErrChallengeRetryNotBefore) {
		t.Errorf("immediate retry: got %v, want ErrChallengeRetryNotBefore", err)
	}
	if err := c.Usable(base.Add(31 * time.Second)); err != nil {
		t.Errorf("retry after the window opened: %v", err)
	}
	if err := c.Usable(base.Add(10 * time.Minute)); !errors.Is(err, ErrChallengeExpired) {
		t.Errorf("retry after expiry: got %v, want ErrChallengeExpired", err)
	}

	// The object is deterministic and identifiable.
	digest, err := c.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	again, err := BuildChallengeFromDecision(dec, params)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	againDigest, err := again.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if !digest.Equal(againDigest) {
		t.Error("identical inputs produced different challenge digests")
	}
}
