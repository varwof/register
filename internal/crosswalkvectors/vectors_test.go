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

// TestIICPProfileMapping pins the IICP capability-set mapping: the profile
// carries id, params and constraints through unchanged and leaves the trace
// linkage to checkProfilePair.
func TestIICPProfileMapping(t *testing.T) {
	src := []byte(`{"grant_id":"g-1","capabilities":[{"id":"a/b:c:d","params":{"n":1},"constraints":["x:y"]}]}`)
	grants, err := MapProfile("iicp->clc-v1", src)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("mapped %d grants, want 1", len(grants))
	}
	if grants[0].ID != "a/b:c:d" {
		t.Fatalf("id = %q", grants[0].ID)
	}
	if got := grants[0].Params["n"]; got != float64(1) {
		t.Fatalf("params[n] = %v", got)
	}
	if len(grants[0].Constraints) != 1 || grants[0].Constraints[0] != "x:y" {
		t.Fatalf("constraints = %v", grants[0].Constraints)
	}
}
