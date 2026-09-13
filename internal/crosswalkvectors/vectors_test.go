// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package crosswalkvectors

import (
	"os"
	"testing"
)

// TestCrosswalkVectors runs the cross-walk corpus from CI.  Where the corpus is
// not checked out this skips, matching the other corpora.
func TestCrosswalkVectors(t *testing.T) {
	path := Path()
	if _, err := os.Stat(path); err != nil {
		alt := "../../../capability/data/_vectors/clc-v1/crosswalk-vectors.json"
		if _, err := os.Stat(alt); err != nil {
			t.Skipf("cross-walk corpus unavailable (%v); set CLC_CROSSWALK_VECTORS to run it", err)
		}
		path = alt
	}
	vectors, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(vectors) < 8 {
		t.Fatalf("corpus has %d vectors, expected the full cross-walk set", len(vectors))
	}
	failures := 0
	for _, r := range Run(vectors) {
		if r.Pass {
			continue
		}
		failures++
		t.Errorf("%s (%s): want %s, got %s [%s]", r.ID, r.Kind, r.Expect, r.Got, r.Note)
	}
	if failures == 0 {
		t.Logf("ran %d cross-walk vectors", len(vectors))
	}
}

// An unknown profile is an error, never a guess.
func TestUnknownProfileIsRejected(t *testing.T) {
	if _, err := MapProfile("something-else->clc-v1", []byte(`{}`)); err == nil {
		t.Fatal("an unknown cross-walk profile must be rejected")
	}
}
