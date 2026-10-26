// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Lifecycle checks for an evidence report: status-snapshot rollback protection
// and replay-evidence comparison.  Both are report-layer checks; neither
// changes a CLC verdict.
package projection

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/varwof/register/internal/jsonstrict"
	"github.com/varwof/register/semantics"
)

// SnapshotBinding is the accepted status-snapshot coordinate for one component.
// It is deployer-local state: the first accepted report seeds it, and later
// reports may only move it forward.
type SnapshotBinding struct {
	Source         string `json:"source"`
	ComponentType  string `json:"componentType"`
	EvidenceDigest Digest `json:"evidenceDigest"`
	Generation     int64  `json:"generation"`
	Digest         Digest `json:"digest"`
}

// SnapshotState is the accepted snapshot set, keyed by
// (source, componentType, evidenceDigest).  It is a value: Check never mutates
// the receiver.
type SnapshotState map[string]SnapshotBinding

// snapshotKey is the accepted-state coordinate.  NUL is not legal in the
// identifiers, so the key is unambiguous.
func snapshotKey(source, componentType string, evidence Digest) string {
	return source + "\x00" + componentType + "\x00" + string(evidence)
}

// NewSnapshotState builds accepted state from persisted bindings.  Deployers
// restore it from their own storage; the key is derived, never user-supplied.
func NewSnapshotState(bindings ...SnapshotBinding) SnapshotState {
	state := make(SnapshotState, len(bindings))
	for _, binding := range bindings {
		state[snapshotKey(binding.Source, binding.ComponentType, binding.EvidenceDigest)] = binding
	}
	return state
}

// Bindings returns the accepted bindings sorted by key, suitable for
// persistence.
func (s SnapshotState) Bindings() []SnapshotBinding {
	keys := make([]string, 0, len(s))
	for key := range s {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]SnapshotBinding, 0, len(keys))
	for _, key := range keys {
		out = append(out, s[key])
	}
	return out
}

// Check compares the report's declared snapshots with the accepted state and
// returns the next state.  Rules:
//
//   - an older generation for the same component is a rollback;
//   - the same generation with a different digest is a fork;
//   - the same generation with the same digest is idempotent;
//   - a newer generation advances the state.
func (s SnapshotState) Check(rep *Report) (SnapshotState, error) {
	if rep == nil {
		return nil, reportFail(CodeReportShape, "report is nil")
	}
	next := make(SnapshotState, len(s)+len(rep.NativeCheckResults))
	for key, binding := range s {
		next[key] = binding
	}
	for _, result := range rep.NativeCheckResults {
		declared, ok, err := result.snapshotBinding()
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		key := snapshotKey(declared.Source, declared.ComponentType, declared.EvidenceDigest)
		if previous, seen := next[key]; seen {
			switch {
			case declared.Generation < previous.Generation:
				return nil, reportFail(CodeReportSnapshotRollback,
					"check %q snapshot generation %d is older than the accepted %d",
					result.CheckID, declared.Generation, previous.Generation)
			case declared.Generation == previous.Generation && declared.Digest != previous.Digest:
				return nil, reportFail(CodeReportSnapshotFork,
					"check %q snapshot generation %d already holds %s",
					result.CheckID, declared.Generation, previous.Digest)
			}
		}
		next[key] = declared
	}
	return next, nil
}

// snapshotBinding extracts the snapshot coordinate a result declares.  The
// source and the generation must be declared together.
func (r NativeCheckResult) snapshotBinding() (SnapshotBinding, bool, error) {
	hasSource := r.StatusSnapshotSource != ""
	hasGeneration := r.StatusSnapshotGeneration != 0
	if !hasSource && !hasGeneration {
		return SnapshotBinding{}, false, nil
	}
	if !hasSource || !hasGeneration {
		return SnapshotBinding{}, false, reportFail(CodeReportSnapshotMissing,
			"check %q declares only part of the snapshot coordinate", r.CheckID)
	}
	if r.StatusSnapshotGeneration < 1 {
		return SnapshotBinding{}, false, reportFail(CodeReportSnapshotMissing,
			"check %q snapshot generation must be >= 1", r.CheckID)
	}
	if err := r.StatusSnapshotDigest.Validate(); err != nil {
		return SnapshotBinding{}, false, reportFail(CodeReportSnapshotMissing,
			"check %q snapshot digest: %s", r.CheckID, err)
	}
	return SnapshotBinding{
		Source:         r.StatusSnapshotSource,
		ComponentType:  r.ComponentType,
		EvidenceDigest: r.EvidenceDigest,
		Generation:     r.StatusSnapshotGeneration,
		Digest:         r.StatusSnapshotDigest,
	}, true, nil
}

// ReplayVersion is the replay-evidence object version.
const ReplayVersion = "CLC-EVIDENCE-REPLAY-v1"

// ReplayEvidence is the replayable statement behind one native check result.
// Its JCS digest is the result's replayDigest, and verification re-derives
// every bound field instead of trusting the report's copy.
type ReplayEvidence struct {
	Version               string             `json:"@version"`
	CheckID               string             `json:"checkId"`
	ComponentType         string             `json:"componentType"`
	EvidenceDigest        Digest             `json:"evidenceDigest"`
	Outcome               NativeCheckOutcome `json:"outcome"`
	Verifier              string             `json:"verifier"`
	VerifierProfileDigest Digest             `json:"verifierProfileDigest"`
}

// Validate checks the replay object's own shape.
func (r ReplayEvidence) Validate() error {
	if r.Version != ReplayVersion {
		return fmt.Errorf("replay @version must be %q", ReplayVersion)
	}
	if r.CheckID == "" || r.ComponentType == "" || r.Verifier == "" {
		return fmt.Errorf("replay object is missing checkId, componentType or verifier")
	}
	if err := r.EvidenceDigest.Validate(); err != nil {
		return err
	}
	if err := r.VerifierProfileDigest.Validate(); err != nil {
		return err
	}
	if !r.Outcome.Valid() {
		return fmt.Errorf("replay outcome %q is not a closed outcome", r.Outcome)
	}
	return nil
}

// Digest returns the canonical digest of the replay object's JCS form.
func (r ReplayEvidence) Digest() (Digest, error) {
	raw, err := semantics.CanonicalJSON(r)
	if err != nil {
		return "", fmt.Errorf("canonical replay object: %w", err)
	}
	sum := sha256.Sum256(raw)
	return DigestFromBytes(sum[:]), nil
}

// ValidateReplayEvidence checks each result's replay digest against the
// supplied raw replay artifacts.  A digest present in a result always requires
// its artifact; require additionally refuses a result that declares no replay
// digest at all.
func ValidateReplayEvidence(rep *Report, artifacts map[Digest][]byte, require bool) error {
	if rep == nil {
		return reportFail(CodeReportShape, "report is nil")
	}
	for _, result := range rep.NativeCheckResults {
		if result.ReplayDigest.Empty() {
			if require {
				return reportFail(CodeReportReplayMissing,
					"check %q declares no AEC replay digest", result.CheckID)
			}
			continue
		}
		raw, ok := artifacts[result.ReplayDigest]
		if !ok {
			return reportFail(CodeReportReplayMissing,
				"check %q replay artifact %s is not supplied", result.CheckID, result.ReplayDigest)
		}
		sum := sha256.Sum256(raw)
		if DigestFromBytes(sum[:]) != result.ReplayDigest {
			return reportFail(CodeReportReplayMismatch,
				"check %q replay artifact does not hash to %s", result.CheckID, result.ReplayDigest)
		}
		if err := jsonstrict.Check(raw); err != nil {
			return reportFail(CodeReportReplayMismatch, "check %q replay artifact: %s", result.CheckID, err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var replay ReplayEvidence
		if err := dec.Decode(&replay); err != nil {
			return reportFail(CodeReportReplayMismatch, "check %q replay artifact: %s", result.CheckID, err)
		}
		if err := replay.Validate(); err != nil {
			return reportFail(CodeReportReplayMismatch, "check %q replay artifact: %s", result.CheckID, err)
		}
		if err := replayMatchesResult(replay, result); err != nil {
			return reportFail(CodeReportReplayMismatch, "check %q: %s", result.CheckID, err)
		}
	}
	return nil
}

// replayMatchesResult requires the replay object to reproduce the result's
// identity and outcome exactly.
func replayMatchesResult(replay ReplayEvidence, result NativeCheckResult) error {
	if replay.CheckID != result.CheckID ||
		replay.ComponentType != result.ComponentType ||
		replay.EvidenceDigest != result.EvidenceDigest ||
		replay.Outcome != result.Outcome ||
		replay.Verifier != result.Verifier ||
		replay.VerifierProfileDigest != result.VerifierProfileDigest {
		return fmt.Errorf("replay evidence does not reproduce the result")
	}
	return nil
}

// CheckReportLifecycle runs the deployer's snapshot and replay checks and
// returns the next snapshot state.  It does not verify a signature; callers
// that have not verified one should use ValidateEvidenceReport separately.
func CheckReportLifecycle(rep *Report, policy ReportPolicy) (SnapshotState, error) {
	if len(policy.SnapshotSources) > 0 {
		for _, result := range rep.NativeCheckResults {
			if result.StatusSnapshotSource == "" {
				continue
			}
			allowed := false
			for _, source := range policy.SnapshotSources {
				if result.StatusSnapshotSource == source {
					allowed = true
					break
				}
			}
			if !allowed {
				return nil, reportFail(CodeReportSnapshotSource,
					"check %q snapshot source %q is not allowed",
					result.CheckID, result.StatusSnapshotSource)
			}
		}
	}
	if policy.RequireSnapshotBinding {
		for _, result := range rep.NativeCheckResults {
			if result.Outcome != NativeCheckSuccess && result.Outcome != NativeCheckFailed {
				continue
			}
			if _, ok, err := result.snapshotBinding(); err != nil {
				return nil, err
			} else if !ok {
				return nil, reportFail(CodeReportSnapshotMissing,
					"check %q has no snapshot coordinate", result.CheckID)
			}
		}
	}
	next, err := policy.Snapshots.Check(rep)
	if err != nil {
		return nil, err
	}
	if err := ValidateReplayEvidence(rep, policy.ReplayEvidence, policy.RequireReplay); err != nil {
		return nil, err
	}
	return next, nil
}
