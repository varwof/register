// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package ocmp

import (
	"encoding/json"
	"os"
	"testing"
)

type jsonStatus struct {
	Present      bool  `json:"present"`
	Verified     bool  `json:"verified"`
	AsOf         int64 `json:"as_of"`
	ValidUntil   int64 `json:"valid_until"`
	Version      int64 `json:"version"`
	LastAccepted int64 `json:"last_accepted"`
}

type jsonInputs struct {
	GrantCovers       bool       `json:"grant_covers"`
	TrustAnchor       bool       `json:"trust_anchor"`
	LocalPolicy       bool       `json:"local_policy"`
	Status            jsonStatus `json:"status"`
	CredentialExpired bool       `json:"credential_expired"`
	Revoked           bool       `json:"revoked"`
	ReplayEnabled     bool       `json:"replay_enabled"`
	Counter           int64      `json:"counter"`
	LastConsumed      int64      `json:"last_consumed"`
	RequiredFact      bool       `json:"required_fact"`
	FactAvailable     bool       `json:"fact_available"`
	TrustedTime       int64      `json:"trusted_time"`
	ClockOffset       int64      `json:"clock_offset"`
	ClockTolerance    int64      `json:"clock_tolerance"`
}

type jsonVector struct {
	ID     string     `json:"id"`
	Inputs jsonInputs `json:"inputs"`
	Expect struct {
		Verdict string `json:"verdict"`
		Reason  string `json:"reason"`
	} `json:"expect"`
}

// TestOfflineVectors runs the structured OCMP corpus directly.
func TestOfflineVectors(t *testing.T) {
	path := os.Getenv("CLC_OCMP_VECTORS")
	if path == "" {
		const def = "../../capability/data/_vectors/clc-v1/offline-vectors.json"
		if _, err := os.Stat(def); err == nil {
			path = def
		} else {
			path = "../capability/data/_vectors/clc-v1/offline-vectors.json"
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("OCMP corpus unavailable: %v", err)
	}
	var doc struct {
		Vectors []jsonVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("corpus: %v", err)
	}
	if len(doc.Vectors) != 12 {
		t.Fatalf("expected 12 vectors, got %d", len(doc.Vectors))
	}
	for _, v := range doc.Vectors {
		in := Inputs{
			GrantCovers: v.Inputs.GrantCovers,
			TrustAnchor: v.Inputs.TrustAnchor,
			LocalPolicy: v.Inputs.LocalPolicy,
			Status: Status{
				Present: v.Inputs.Status.Present, Verified: v.Inputs.Status.Verified,
				AsOf: v.Inputs.Status.AsOf, ValidUntil: v.Inputs.Status.ValidUntil,
				Version: v.Inputs.Status.Version, LastAccepted: v.Inputs.Status.LastAccepted,
			},
			CredentialExpired: v.Inputs.CredentialExpired,
			Revoked:           v.Inputs.Revoked,
			ReplayEnabled:     v.Inputs.ReplayEnabled,
			Counter:           v.Inputs.Counter,
			LastConsumed:      v.Inputs.LastConsumed,
			RequiredFact:      v.Inputs.RequiredFact,
			FactAvailable:     v.Inputs.FactAvailable,
			TrustedTime:       v.Inputs.TrustedTime,
			ClockOffset:       v.Inputs.ClockOffset,
			ClockTolerance:    v.Inputs.ClockTolerance,
		}
		got := Evaluate(in)
		if got.Verdict != v.Expect.Verdict || got.Reason != v.Expect.Reason {
			t.Errorf("%s: got %s/%s, want %s/%s", v.ID, got.Verdict, got.Reason, v.Expect.Verdict, v.Expect.Reason)
		}
	}
}
