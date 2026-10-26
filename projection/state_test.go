// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/varwof/register/projection"
)

func TestSnapshotStateFileRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report := reportWithSnapshot(t, now, 5, testDigest('1'))
	state, err := projection.SnapshotState(nil).Check(report)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := state.MarshalState()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := projection.ParseState(raw)
	if err != nil {
		t.Fatalf("parse state: %v", err)
	}
	if len(parsed.Bindings()) != 1 || parsed.Bindings()[0].Generation != 5 {
		t.Fatalf("bindings = %+v", parsed.Bindings())
	}
	if _, err := parsed.Check(report); err != nil {
		t.Fatalf("restored state rejected the same report: %v", err)
	}
	if _, err := parsed.Check(reportWithSnapshot(t, now, 4, testDigest('1'))); err == nil {
		t.Fatal("restored state lost rollback protection")
	}
}

func TestParseStateRejectsBadInput(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	report := reportWithSnapshot(t, now, 5, testDigest('1'))
	state, err := projection.SnapshotState(nil).Check(report)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := state.MarshalState()
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["@version"] = "CLC-EVIDENCE-STATE-v0"
	badVersion, _ := json.Marshal(doc)
	if _, err := projection.ParseState(badVersion); err == nil {
		t.Fatal("wrong state version accepted")
	}

	doc["@version"] = projection.StateVersion
	doc["snapshots"] = append(doc["snapshots"].([]any), doc["snapshots"].([]any)[0])
	duplicate, _ := json.Marshal(doc)
	if _, err := projection.ParseState(duplicate); err == nil {
		t.Fatal("duplicate snapshot coordinate accepted")
	}

	if _, err := projection.ParseState(append(raw, []byte("{}")...)); err == nil {
		t.Fatal("trailing state data accepted")
	}
}

func TestDecodeSignedReportStrict(t *testing.T) {
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	env, _, _, _ := signedReport(t, now, "principal:report-verifier")
	signed := &projection.SignedReport{Envelope: env}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projection.DecodeSignedReport(raw); err != nil {
		t.Fatalf("round trip: %v", err)
	}

	if _, err := projection.DecodeSignedReport(append(raw, []byte("{}")...)); err == nil {
		t.Fatal("trailing data accepted")
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["extra"] = true
	withExtra, _ := json.Marshal(doc)
	if _, err := projection.DecodeSignedReport(withExtra); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown member error = %v", err)
	}
}
