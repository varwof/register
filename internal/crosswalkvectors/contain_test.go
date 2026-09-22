// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package crosswalkvectors

import (
	"os"
	"testing"
)

// TestContainCrosswalkVectors runs the CLC-D containment cross-walk corpus from
// CI.  Where the corpus is not checked out this skips, matching the other
// corpora.
func TestContainCrosswalkVectors(t *testing.T) {
	path := ContainPath()
	if _, err := os.Stat(path); err != nil {
		alt := "../../../capability/data/_vectors/clc-d/containment-crosswalk-vectors.json"
		if _, err := os.Stat(alt); err != nil {
			t.Skipf("CLC-D cross-walk corpus unavailable (%v); set CLC_D_CROSSWALK_VECTORS to run it", err)
		}
		path = alt
	}
	vectors, err := LoadContain(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(vectors) < 10 {
		t.Fatalf("corpus has %d vectors, expected the full CLC-D cross-walk set", len(vectors))
	}
	failures := 0
	for _, r := range RunContain(vectors) {
		if r.Pass {
			continue
		}
		failures++
		t.Errorf("%s (%s): want %s, got %s [%s]", r.ID, r.Kind, r.Expect, r.Got, r.Note)
	}
	if failures == 0 {
		t.Logf("ran %d CLC-D cross-walk vectors", len(vectors))
	}
}
