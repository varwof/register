// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection_test

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/projection"
	"github.com/varwof/register/semantics"
)

// reportWithSnapshot mutates the single result of a consistent report to
// declare a status-snapshot coordinate.
func reportWithSnapshot(t *testing.T, now time.Time, generation int64, digest projection.Digest) *projection.Report {
	t.Helper()
	report, _ := consistentProfileReport(t, now)
	report.NativeCheckResults[0].StatusSnapshotSource = "aeb-status"
	report.NativeCheckResults[0].StatusSnapshotGeneration = generation
	report.NativeCheckResults[0].StatusSnapshotDigest = digest
	return report
}

func TestSnapshotStateRejectsRollbackAndFork(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	first := reportWithSnapshot(t, now, 5, testDigest('1'))
	state, err := projection.SnapshotState(nil).Check(first)
	if err != nil {
		t.Fatalf("seed state: %v", err)
	}

	same, err := state.Check(reportWithSnapshot(t, now, 5, testDigest('1')))
	if err != nil {
		t.Fatalf("idempotent generation rejected: %v", err)
	}
	if len(same) != 1 {
		t.Fatalf("idempotent check changed the state: %+v", same)
	}

	_, err = state.Check(reportWithSnapshot(t, now, 4, testDigest('1')))
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportSnapshotRollback) {
		t.Fatalf("rollback error = %v", err)
	}

	_, err = state.Check(reportWithSnapshot(t, now, 5, testDigest('2')))
	if err == nil || !strings.Contains(err.Error(), projection.CodeReportSnapshotFork) {
		t.Fatalf("fork error = %v", err)
	}

	advanced, err := state.Check(reportWithSnapshot(t, now, 6, testDigest('3')))
	if err != nil {
		t.Fatalf("advance rejected: %v", err)
	}
	if len(advanced) != 1 {
		t.Fatalf("advanced state = %+v", advanced)
	}
	for _, binding := range advanced {
		if binding.Generation != 6 || binding.Digest != testDigest('3') {
			t.Fatalf("advanced binding = %+v", binding)
		}
	}
}

// Accepted state must survive a persist/restore round trip, or rollback
// protection stops working across processes.
func TestSnapshotStatePersistenceRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report := reportWithSnapshot(t, now, 5, testDigest('1'))
	state, err := projection.SnapshotState(nil).Check(report)
	if err != nil {
		t.Fatal(err)
	}
	bindings := state.Bindings()
	if len(bindings) != 1 || bindings[0].Generation != 5 {
		t.Fatalf("bindings = %+v", bindings)
	}
	restored := projection.NewSnapshotState(bindings...)
	if _, err := restored.Check(report); err != nil {
		t.Fatalf("restored state rejected the same report: %v", err)
	}
	if _, err := restored.Check(reportWithSnapshot(t, now, 4, testDigest('1'))); err == nil {
		t.Fatal("restored state lost rollback protection")
	}
}

func TestSnapshotCoordinateMustBeComplete(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	report.NativeCheckResults[0].StatusSnapshotSource = "aeb-status"
	// Generation deliberately left at zero.
	if _, err := projection.SnapshotState(nil).Check(report); err == nil ||
		!strings.Contains(err.Error(), projection.CodeReportSnapshotMissing) {
		t.Fatalf("incomplete coordinate error = %v", err)
	}
}

func TestRequireSnapshotBinding(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	if _, err := projection.CheckReportLifecycle(report, projection.ReportPolicy{
		RequireSnapshotBinding: true,
	}); err == nil || !strings.Contains(err.Error(), projection.CodeReportSnapshotMissing) {
		t.Fatalf("missing snapshot coordinate error = %v", err)
	}
	bounded := reportWithSnapshot(t, now, 3, testDigest('4'))
	if _, err := projection.CheckReportLifecycle(bounded, projection.ReportPolicy{
		RequireSnapshotBinding: true,
	}); err != nil {
		t.Fatalf("bounded report rejected: %v", err)
	}
}

// replayFor builds the replay object that reproduces one result.
func replayFor(t *testing.T, report *projection.Report) (projection.ReplayEvidence, []byte, projection.Digest) {
	t.Helper()
	result := report.NativeCheckResults[0]
	replay := projection.ReplayEvidence{
		Version:               projection.ReplayVersion,
		CheckID:               result.CheckID,
		ComponentType:         result.ComponentType,
		EvidenceDigest:        result.EvidenceDigest,
		Outcome:               result.Outcome,
		Verifier:              result.Verifier,
		VerifierProfileDigest: result.VerifierProfileDigest,
	}
	raw, err := semantics.CanonicalJSON(replay)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := replay.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return replay, raw, digest
}

func TestReplayEvidenceRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	_, raw, digest := replayFor(t, report)
	report.NativeCheckResults[0].ReplayDigest = digest
	artifacts := map[projection.Digest][]byte{digest: raw}

	if err := projection.ValidateReplayEvidence(report, artifacts, true); err != nil {
		t.Fatalf("valid replay evidence rejected: %v", err)
	}
	if _, err := projection.CheckReportLifecycle(report, projection.ReportPolicy{
		ReplayEvidence: artifacts,
		RequireReplay:  true,
	}); err != nil {
		t.Fatalf("lifecycle rejected valid replay: %v", err)
	}
}

func TestReplayEvidenceRejectsMismatches(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	replay, _, digest := replayFor(t, report)
	report.NativeCheckResults[0].ReplayDigest = digest

	// Artifact bytes that do not hash to the declared digest.
	if err := projection.ValidateReplayEvidence(report, map[projection.Digest][]byte{
		digest: []byte(`{"tampered":true}`),
	}, true); err == nil || !strings.Contains(err.Error(), projection.CodeReportReplayMismatch) {
		t.Fatalf("tampered replay error = %v", err)
	}

	// A replay object that does not reproduce the result.
	changed := replay
	changed.Outcome = projection.NativeCheckFailed
	changedRaw, err := semantics.CanonicalJSON(changed)
	if err != nil {
		t.Fatal(err)
	}
	changedDigest, err := changed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	changedReport, _ := consistentProfileReport(t, now)
	changedReport.NativeCheckResults[0].ReplayDigest = changedDigest
	if err := projection.ValidateReplayEvidence(changedReport, map[projection.Digest][]byte{
		changedDigest: changedRaw,
	}, true); err == nil || !strings.Contains(err.Error(), projection.CodeReportReplayMismatch) {
		t.Fatalf("non-reproducing replay error = %v", err)
	}

	// Declared digest with no supplied artifact.
	if err := projection.ValidateReplayEvidence(report, nil, false); err == nil ||
		!strings.Contains(err.Error(), projection.CodeReportReplayMissing) {
		t.Fatalf("missing artifact error = %v", err)
	}
}

func TestReplayEvidenceOptionalAndRequired(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	if err := projection.ValidateReplayEvidence(report, nil, false); err != nil {
		t.Fatalf("optional replay rejected: %v", err)
	}
	if err := projection.ValidateReplayEvidence(report, nil, true); err == nil ||
		!strings.Contains(err.Error(), projection.CodeReportReplayMissing) {
		t.Fatalf("required replay error = %v", err)
	}
}

// A signed report carries its snapshot coordinate through verification and the
// deployer gets the next state back.
func TestSignedReportReturnsNextSnapshotState(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report, _ := consistentProfileReport(t, now)
	report.NativeCheckResults[0].StatusSnapshotSource = "aeb-status"
	report.NativeCheckResults[0].StatusSnapshotGeneration = 7
	report.NativeCheckResults[0].StatusSnapshotDigest = testDigest('7')
	bindVerifier(report, "principal:report-verifier")
	cert, key := testVerifierCert(t, "corp.example", "report-verifier", now)
	env, err := projection.SignEvidenceReport(report, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := projection.VerifySignedEvidenceReport(env, policyWithPins(report, projection.ReportPolicy{
		Roots:                  []*x509.Certificate{cert},
		Now:                    now,
		RequireSnapshotBinding: true,
	}))
	if err != nil {
		t.Fatalf("signed report rejected: %v", err)
	}
	if len(state) != 1 {
		t.Fatalf("next snapshot state = %+v", state)
	}
	for _, binding := range state {
		if binding.Generation != 7 {
			t.Fatalf("binding = %+v", binding)
		}
	}
}
