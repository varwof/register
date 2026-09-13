// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// CLC-CHALLENGE-v1 — what is still missing, said in a machine.
//
// Both sides of the language can end in "not yet": the authorization side
// returns allow_unresolved (§8.4 residual obligations), the evidence side
// returns unknown (a constraint the core must not answer) or a violated
// requirement with roles nobody filled.  Refusing without saying what would fix
// it is what makes an evidence system unusable: the agent can only retry the
// same request.  The Authorization Evidence Challenge (AE-CHALLENGE §2) is the
// published treatment of that message, and this object follows it:
//
//	{ "@version": "CLC-CHALLENGE-v1", "challenge_id": ..., "nonce": ...,
//	  "audience": ..., "action_digest": ..., "requirement_id": ...,
//	  "requirement_digest": ..., "required": [ {id, constraint, reason} ],
//	  "obtain_hints": [...], "retry_timing": {not_before, jitter_sec},
//	  "expires_at": ... }
//
// Non-negotiables carried over from the challenge specification:
//
//   - a challenge **authorizes nothing**, promises nothing, and transfers no
//     admission ownership.  Authorizes() exists so a caller cannot mistake it
//     for a verdict;
//   - it is bound to one exact action (action_digest) and to one requirement
//     revision (requirement_digest), so it cannot be transplanted to another
//     action or used to weaken the bar;
//   - retrying can amplify load, so retry timing is explicit (not_before plus
//     per-challenge jitter) and the challenge expires;
//   - the nonce is caller-generated and unpredictable: single-use handling of
//     the retry lives at the enforcement point, which is also the only place
//     that can bound outstanding challenges.

package semantics

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// ChallengeVersion is the only @version this revision accepts.
const ChallengeVersion = "CLC-CHALLENGE-v1"

const (
	minChallengeNonceBytes = 8
	maxChallengeNonceBytes = 128
	maxChallengeJitterSec  = 300
)

// ChallengeItem names one outstanding thing: an evidence role, or an obligation
// identity such as "varwof/constraint-v1:time".
type ChallengeItem struct {
	ID         string `json:"id"`
	Constraint string `json:"constraint,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// ObtainHint tells the requester where the outstanding item can be obtained.
type ObtainHint struct {
	ID        string `json:"id"`
	Mechanism string `json:"mechanism,omitempty"`
	URI       string `json:"uri,omitempty"`
}

// RetryTiming bounds when a corrected presentation may be attempted.
type RetryTiming struct {
	NotBefore time.Time `json:"not_before"`
	JitterSec int       `json:"jitter_sec,omitempty"`
}

// Challenge is a machine-readable statement of what evidence or confirmation is
// still required.  It is not a verdict.
type Challenge struct {
	Version           string          `json:"@version"`
	ID                string          `json:"challenge_id"`
	Nonce             string          `json:"nonce"`
	Audience          string          `json:"audience,omitempty"`
	ActionDigest      Digest          `json:"action_digest"`
	RequirementID     string          `json:"requirement_id,omitempty"`
	RequirementDigest *Digest         `json:"requirement_digest,omitempty"`
	Required          []ChallengeItem `json:"required"`
	ObtainHints       []ObtainHint    `json:"obtain_hints,omitempty"`
	Retry             *RetryTiming    `json:"retry_timing,omitempty"`
	ExpiresAt         time.Time       `json:"expires_at"`
}

// ChallengeParams are the caller-supplied inputs a challenge needs.  ID and
// Nonce are the caller's: the core does not generate randomness.
type ChallengeParams struct {
	ID           string
	Nonce        string
	Audience     string
	ActionDigest Digest
	Now          time.Time
	TTL          time.Duration
	ObtainHints  []ObtainHint
	Retry        *RetryTiming
}

var (
	// ErrChallengeShape means the challenge is malformed (missing identity,
	// unusable action digest, bad retry timing, non-UTC instant).
	ErrChallengeShape = errors.New("challenge_shape")
	// ErrChallengeExpired means the challenge may no longer drive a retry.
	ErrChallengeExpired = errors.New("challenge_expired")
	// ErrChallengeNotOutstanding means the caller asked for a challenge for a
	// result that needs none — nothing is missing.
	ErrChallengeNotOutstanding = errors.New("challenge_not_outstanding")
	// ErrChallengeRetryNotBefore means the challenge's own retry schedule has
	// not opened yet; retrying now is exactly the amplification it guards
	// against.
	ErrChallengeRetryNotBefore = errors.New("challenge_retry_not_before")
)

// Authorizes reports whether a challenge authorizes anything.  It never does;
// the method exists so that call sites cannot read one as a verdict by accident.
func (c Challenge) Authorizes() bool { return false }

// BuildChallengeFromRequirement builds the challenge for an evidence
// requirement that was not satisfied.  A satisfied result needs no challenge,
// and a hard denial with nothing missing is reported as such rather than dressed
// up as a retryable request.
func BuildChallengeFromRequirement(req Requirement, result RequirementResult, params ChallengeParams) (Challenge, error) {
	if err := req.Validate(); err != nil {
		return Challenge{}, err
	}
	if result.Verdict == EvidenceSatisfied {
		return Challenge{}, fmt.Errorf("%w: requirement %s is satisfied", ErrChallengeNotOutstanding, req.ID)
	}

	var required []ChallengeItem
	for _, role := range result.MissingRoles {
		required = append(required, ChallengeItem{ID: role, Reason: "role_unfilled"})
	}
	for _, evaluation := range result.Constraints {
		if evaluation.Verdict == EvidenceSatisfied {
			continue
		}
		required = append(required, ChallengeItem{
			ID:         evaluation.Constraint,
			Constraint: evaluation.Constraint,
			Reason:     evaluation.Reason,
		})
	}
	if len(required) == 0 {
		return Challenge{}, fmt.Errorf("%w: requirement %s reported no outstanding item", ErrChallengeNotOutstanding, req.ID)
	}

	digest, err := req.Digest()
	if err != nil {
		return Challenge{}, err
	}
	c := Challenge{
		Version:           ChallengeVersion,
		ID:                params.ID,
		Nonce:             params.Nonce,
		Audience:          params.Audience,
		ActionDigest:      params.ActionDigest,
		RequirementID:     req.ID,
		RequirementDigest: &digest,
		Required:          sortedChallengeItems(required),
		ObtainHints:       params.ObtainHints,
		Retry:             params.Retry,
		ExpiresAt:         params.Now.UTC().Add(params.TTL),
	}
	if err := c.Validate(); err != nil {
		return Challenge{}, err
	}
	return c, nil
}

// BuildChallengeFromDecision builds the challenge for an authorization decision
// carrying §8.4 residual obligations: the consumer could not discharge them, so
// it says which ones it owes an answer for.
func BuildChallengeFromDecision(d Decision, params ChallengeParams) (Challenge, error) {
	if err := checkDecisionShape(d); err != nil {
		return Challenge{}, err
	}
	if d.Verdict != VerdictAllowUR {
		return Challenge{}, fmt.Errorf("%w: verdict %s carries no residual obligation", ErrChallengeNotOutstanding, d.Verdict)
	}
	items := make([]ChallengeItem, 0, len(d.Unresolved))
	for _, obligation := range d.Unresolved {
		identity, err := ConstraintIdentity(obligation)
		if err != nil {
			return Challenge{}, err
		}
		items = append(items, ChallengeItem{ID: identity, Constraint: obligation, Reason: "obligation_undischarged"})
	}
	c := Challenge{
		Version:      ChallengeVersion,
		ID:           params.ID,
		Nonce:        params.Nonce,
		Audience:     params.Audience,
		ActionDigest: params.ActionDigest,
		Required:     sortedChallengeItems(items),
		ObtainHints:  params.ObtainHints,
		Retry:        params.Retry,
		ExpiresAt:    params.Now.UTC().Add(params.TTL),
	}
	if err := c.Validate(); err != nil {
		return Challenge{}, err
	}
	return c, nil
}

// Validate checks the challenge's shape and bindings.
func (c Challenge) Validate() error {
	if c.Version != ChallengeVersion {
		return fmt.Errorf("%w: version %q", ErrChallengeShape, c.Version)
	}
	if c.ID == "" {
		return fmt.Errorf("%w: challenge_id required", ErrChallengeShape)
	}
	if n := len(c.Nonce); n < minChallengeNonceBytes || n > maxChallengeNonceBytes {
		return fmt.Errorf("%w: nonce must be %d..%d bytes", ErrChallengeShape, minChallengeNonceBytes, maxChallengeNonceBytes)
	}
	if !digestUsable(c.ActionDigest) {
		return fmt.Errorf("%w: action_digest required", ErrChallengeShape)
	}
	if c.RequirementDigest != nil && !digestUsable(*c.RequirementDigest) {
		return fmt.Errorf("%w: unusable requirement_digest", ErrChallengeShape)
	}
	if len(c.Required) == 0 {
		return fmt.Errorf("%w: nothing required", ErrChallengeShape)
	}
	for _, item := range c.Required {
		if item.ID == "" {
			return fmt.Errorf("%w: required item without an id", ErrChallengeShape)
		}
	}
	if c.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: expires_at required", ErrChallengeShape)
	}
	if c.ExpiresAt.Location() != time.UTC {
		return fmt.Errorf("%w: expires_at must be UTC", ErrChallengeShape)
	}
	if c.Retry != nil {
		if c.Retry.NotBefore.IsZero() || c.Retry.NotBefore.Location() != time.UTC {
			return fmt.Errorf("%w: retry_timing.not_before must be a UTC instant", ErrChallengeShape)
		}
		if c.Retry.JitterSec < 0 || c.Retry.JitterSec > maxChallengeJitterSec {
			return fmt.Errorf("%w: jitter_sec out of range", ErrChallengeShape)
		}
		if c.Retry.NotBefore.After(c.ExpiresAt) {
			return fmt.Errorf("%w: retry_timing.not_before is after expiry", ErrChallengeShape)
		}
	}
	return nil
}

// Usable reports whether the challenge may still drive a retry at now.  An
// expired challenge is dead: retrying against it is the load amplification the
// challenge specification warns about.
func (c Challenge) Usable(now time.Time) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if !now.UTC().Before(c.ExpiresAt) {
		return fmt.Errorf("%w: expired at %s", ErrChallengeExpired, c.ExpiresAt.Format(time.RFC3339))
	}
	if c.Retry != nil && now.UTC().Before(c.Retry.NotBefore) {
		return fmt.Errorf("%w: opens at %s", ErrChallengeRetryNotBefore, c.Retry.NotBefore.Format(time.RFC3339))
	}
	return nil
}

// Digest binds the challenge so a caller can identify exactly which challenge it
// answered.
func (c Challenge) Digest() (Digest, error) {
	if err := c.Validate(); err != nil {
		return Digest{}, err
	}
	return DigestOf(c)
}

// sortedChallengeItems orders the outstanding items deterministically, so the
// same inputs produce the same challenge bytes.
func sortedChallengeItems(items []ChallengeItem) []ChallengeItem {
	out := append([]ChallengeItem(nil), items...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		if out[i].Constraint != out[j].Constraint {
			return out[i].Constraint < out[j].Constraint
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}
