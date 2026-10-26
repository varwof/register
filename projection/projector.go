// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/varwof/register/semantics"
)

// ProjectedView is the minimal view the CLC decision layer needs from an
// external evidence document.
type ProjectedView struct {
	Action      *semantics.ActionId
	Facts       []semantics.EvidenceFact
	Requirement *semantics.Requirement
	// SourceRequirementDigest is the JCS SHA-256 of the complete source
	// requirement as received, before any projection.  It is report evidence
	// and is never a member of the CLC Requirement or Satisfaction objects.
	SourceRequirementDigest *semantics.Digest
	// ProjectedRequirementDigest is the CLC requirement digest over the final,
	// validated CLC-REQUIREMENT-v1 object after all rewriting.
	ProjectedRequirementDigest *semantics.Digest
	Residuals                  []string
	// RequiredNativeChecks are display obligations ("what should run"), which
	// may include non-check obligations such as a required relation.
	RequiredNativeChecks []string
	// RequiredCheckIDs are the check ids that must have at least one explicit
	// result for the report to be complete.  They are plain identifiers: no
	// carrier-specific prefix is interpreted.
	RequiredCheckIDs []string
	Meta             map[string]string
}

// NativeCheckOutcome is the closed outcome of one required native status
// check.  CLC never fetches status itself: the native profile runs the check
// and records which of these four results it obtained.
//
// The four outcomes are deliberately distinct.  Collapsing them loses the
// difference between "the artifact was checked and is ineligible" and "the
// check could not be run": only the first is evidence about the artifact.
type NativeCheckOutcome string

const (
	// NativeCheckSuccess means the required native status check ran and
	// passed.  Only a success can be a precondition for an eligible Fact.
	NativeCheckSuccess NativeCheckOutcome = "success"
	// NativeCheckFailed means the check ran and the artifact is ineligible.
	// A verified revoked status is failed, never unavailable.
	NativeCheckFailed NativeCheckOutcome = "failed"
	// NativeCheckUnavailable means a required source or result could not be
	// obtained or evaluated.
	NativeCheckUnavailable NativeCheckOutcome = "unavailable"
	// NativeCheckNotApplicable means the profile explicitly establishes that
	// this check does not apply to the component.
	NativeCheckNotApplicable NativeCheckOutcome = "not_applicable"
)

// Valid reports whether o is one of the four closed outcomes.
func (o NativeCheckOutcome) Valid() bool {
	switch o {
	case NativeCheckSuccess, NativeCheckFailed, NativeCheckUnavailable, NativeCheckNotApplicable:
		return true
	}
	return false
}

// NativeCheckResult is the explicit report record for one native status check
// of one component.  The absence of an unavailable entry is not a success:
// every required check MUST produce a record, including a successful one.
//
// Every result identifies the artifact and the verifier/profile that produced
// the outcome.  A success or failure also identifies the trust and status
// snapshots and the freshness decision on which it rested.  An unavailable or
// not-applicable outcome may have no status snapshot, but it still identifies
// the artifact to which it applies and must not be inferred from an empty list.
type NativeCheckResult struct {
	// CheckID names the required native check, e.g.
	// "status_required:ep-quorum".
	CheckID string `json:"checkId"`
	// ComponentType is the native component type the check ran over.  Several
	// components may share one type; EvidenceDigest then identifies which one.
	ComponentType string `json:"componentType"`
	// EvidenceDigest is the component's AEC evidence digest, or another stable
	// per-component identity when several components share one type.  It is
	// the profile's statement of which artifact the check ran over, so it is
	// typed: two spellings of one digest must not produce two report bytes.
	EvidenceDigest Digest `json:"evidenceDigest,omitempty"`
	// Outcome is one of the four closed outcomes.
	Outcome NativeCheckOutcome `json:"outcome"`
	// Reason is the stable native reason.  Required for failed, unavailable
	// and not_applicable so the report never records an unexplained refusal.
	Reason string `json:"reason,omitempty"`
	// Verifier identifies the verifier that produced the result.
	Verifier string `json:"verifier,omitempty"`
	// VerifierProfileDigest pins the verifier's profile.
	VerifierProfileDigest Digest `json:"verifierProfileDigest,omitempty"`
	// TrustSnapshotDigest is the trust-input or trust-snapshot digest used for
	// acceptance.
	TrustSnapshotDigest Digest `json:"trustSnapshotDigest,omitempty"`
	// StatusSnapshotDigest is the authenticated status snapshot the decision
	// rested on.  A cached snapshot is acceptable when the native freshness
	// rules permit it; CLC does not refresh it.
	StatusSnapshotDigest Digest `json:"statusSnapshotDigest,omitempty"`
	// StatusSnapshotSource names the authority that produced the snapshot.
	// Together with StatusSnapshotGeneration it forms the rollback coordinate.
	StatusSnapshotSource string `json:"statusSnapshotSource,omitempty"`
	// StatusSnapshotGeneration is the snapshot's generation/epoch.  Reports
	// consumed by a deployer that keeps accepted state may only advance it.
	StatusSnapshotGeneration int64 `json:"statusSnapshotGeneration,omitempty"`
	// VerificationTime is when the native check ran.
	VerificationTime time.Time `json:"verificationTime,omitempty"`
	// FreshnessDecision records the native freshness decision for the snapshot
	// that was used.  It is typed so "cached within the window" and "stale"
	// cannot be flattened into one free-form string.
	FreshnessDecision *FreshnessDecision `json:"freshnessDecision,omitempty"`
	// ReplayDigest is the corresponding AEC replay evidence digest when one
	// is available.
	ReplayDigest Digest `json:"replayDigest,omitempty"`
}

// validate enforces the closed outcome set and the attribution contract.
func (r NativeCheckResult) validate(index int) error {
	if strings.TrimSpace(r.CheckID) == "" {
		return fmt.Errorf("native check result %d has no checkId", index)
	}
	if strings.TrimSpace(r.ComponentType) == "" {
		return fmt.Errorf("native check result %d (%s) has no componentType", index, r.CheckID)
	}
	if !r.Outcome.Valid() {
		return fmt.Errorf("native check result %d (%s) has unknown outcome %q", index, r.CheckID, r.Outcome)
	}
	if err := r.EvidenceDigest.Validate(); err != nil {
		return fmt.Errorf("native check result %d (%s) evidence digest: %w", index, r.CheckID, err)
	}
	if strings.TrimSpace(r.Verifier) == "" {
		return fmt.Errorf("native check result %d (%s) is not attributable to a verifier", index, r.CheckID)
	}
	if err := r.VerifierProfileDigest.Validate(); err != nil {
		return fmt.Errorf("native check result %d (%s) verifier/profile digest: %w", index, r.CheckID, err)
	}
	if r.VerificationTime.IsZero() {
		return fmt.Errorf("native check result %d (%s) has no verification time", index, r.CheckID)
	}
	if !r.ReplayDigest.Empty() {
		if err := r.ReplayDigest.Validate(); err != nil {
			return fmt.Errorf("native check result %d (%s) AEC replay digest: %w", index, r.CheckID, err)
		}
	}
	switch r.Outcome {
	case NativeCheckSuccess:
	case NativeCheckFailed:
		if strings.TrimSpace(r.Reason) == "" {
			return fmt.Errorf("native check result %d (%s) reports failure without a reason", index, r.CheckID)
		}
	case NativeCheckUnavailable, NativeCheckNotApplicable:
		if strings.TrimSpace(r.Reason) == "" {
			return fmt.Errorf("native check result %d (%s) reports %s without a reason", index, r.CheckID, r.Outcome)
		}
	}
	if r.Outcome == NativeCheckSuccess || r.Outcome == NativeCheckFailed {
		if err := r.TrustSnapshotDigest.Validate(); err != nil {
			return fmt.Errorf("native check result %d (%s) trust-snapshot digest: %w", index, r.CheckID, err)
		}
		if err := r.StatusSnapshotDigest.Validate(); err != nil {
			return fmt.Errorf("native check result %d (%s) status-snapshot digest: %w", index, r.CheckID, err)
		}
		if r.FreshnessDecision == nil {
			return fmt.Errorf("native check result %d (%s) has no freshness decision", index, r.CheckID)
		}
		if err := r.FreshnessDecision.Validate(); err != nil {
			return fmt.Errorf("native check result %d (%s) freshness: %w", index, r.CheckID, err)
		}
		if r.Outcome == NativeCheckSuccess &&
			r.FreshnessDecision.Verdict != FreshnessFresh &&
			r.FreshnessDecision.Verdict != FreshnessCached {
			return fmt.Errorf("native check result %d (%s) reports success with freshness %q",
				index, r.CheckID, r.FreshnessDecision.Verdict)
		}
	}
	return nil
}

// Context carries the pins a projection needs.
type Context struct {
	Now       time.Time
	Initiator string
	Executor  string

	// RoleMap bridges a foreign role/component identifier to the CLC evidence
	// role facts are typed by.  A mapping is never guessed: the relying party
	// pins it (the same way an Action-Mapping Profile is pinned).  An entry
	// that is absent leaves the foreign identifier in place and surfaces a
	// residual instead of silently inventing a bridge.
	RoleMap map[string]string
}

// Projector recognises and projects one external evidence format.
type Projector interface {
	ID() string
	Match(raw []byte) bool
	Project(raw []byte, ctx Context) (ProjectedView, error)
}

// sourceRequirementDigest returns the SHA-256 of the JCS encoding of the
// complete source requirement.  Numbers are decoded as json.Number so the
// canonical bytes do not depend on float64 round-tripping.  Strict JSON and
// duplicate-member rejection are the caller's responsibility.
func sourceRequirementDigest(raw []byte) (semantics.Digest, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var source any
	if err := dec.Decode(&source); err != nil {
		return semantics.Digest{}, fmt.Errorf("decode source requirement: %w", err)
	}
	digest, err := semantics.DigestOf(source)
	if err != nil {
		return semantics.Digest{}, fmt.Errorf("digest source requirement: %w", err)
	}
	return digest, nil
}
