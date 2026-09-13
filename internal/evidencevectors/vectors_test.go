// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package evidencevectors

import (
	"os"
	"testing"
)

// TestEvidenceVectors runs the CLC-E corpus.  The corpus lives in the sibling
// capability module; where it is not checked out this skips rather than failing,
// matching how the authorization-side suite is exercised.
func TestEvidenceVectors(t *testing.T) {
	path := Path()
	if _, err := os.Stat(path); err != nil {
		// go test runs with the package directory as the working directory, so
		// the module-root default does not resolve; fall back to the in-tree
		// location before giving up.
		alt := "../../../capability/data/_vectors/clc-v1/evidence-vectors.json"
		if _, err := os.Stat(alt); err != nil {
			t.Skipf("evidence corpus unavailable (%v); set CLC_EVIDENCE_VECTORS to run it", err)
		}
		path = alt
	}
	vectors, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(vectors) < 20 {
		t.Fatalf("corpus has %d vectors, expected the full evidence set", len(vectors))
	}

	results := Run(vectors)
	failures := 0
	for _, r := range results {
		if r.Pass {
			continue
		}
		failures++
		t.Errorf("%s (%s): want %s, got %s [%s]", r.ID, r.Kind, r.Expect, r.Got, r.Note)
	}
	if failures == 0 {
		t.Logf("ran %d evidence vectors", len(results))
	}
}
