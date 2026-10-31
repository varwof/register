// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package crosswalkvectors

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// TestIICPPairLinkage pins the carrier-level check the CLC relation cannot
// express: the child must name the parent grant it attenuates.
func TestIICPPairLinkage(t *testing.T) {
	parent := []byte(`{"grant_id":"g-1","capabilities":[{"id":"a/b:c"}]}`)
	matching := []byte(`{"parent_grant_id":"g-1","workorder_id":"wo-1","capabilities":[{"id":"a/b:c:d"}]}`)
	other := []byte(`{"parent_grant_id":"g-2","capabilities":[{"id":"a/b:c:d"}]}`)
	missing := []byte(`{"capabilities":[{"id":"a/b:c:d"}]}`)

	if err := checkProfilePair("iicp->clc-v1", parent, matching); err != nil {
		t.Fatalf("matching linkage rejected: %v", err)
	}
	if err := checkProfilePair("iicp->clc-v1", parent, other); err == nil {
		t.Fatal("a child naming a different parent grant was accepted")
	}
	if err := checkProfilePair("iicp->clc-v1", parent, missing); err == nil {
		t.Fatal("a child without parent_grant_id was accepted")
	}
	// A profile with no carrier linkage is unaffected.
	if err := checkProfilePair("aic-jwt-da->clc-v1", parent, other); err != nil {
		t.Fatalf("unrelated profile rejected: %v", err)
	}
}

// TestContainMapErrorExpectation pins the corpus-level expression of a
// profile failure: a vector can assert map_error instead of a relation, and
// the expectation is honoured in both directions.
func TestContainMapErrorExpectation(t *testing.T) {
	parent := json.RawMessage(`{"grant_id":"g-1","capabilities":[{"id":"a/b:c"}]}`)
	mismatched := json.RawMessage(`{"parent_grant_id":"g-2","capabilities":[{"id":"a/b:c:d"}]}`)
	matching := json.RawMessage(`{"parent_grant_id":"g-1","capabilities":[{"id":"a/b:c:d"}]}`)
	v := ContainVector{
		ID:           "ccx-900",
		Kind:         "contain-crosswalk",
		Profile:      "iicp->clc-v1",
		ParentSource: parent,
		ChildSource:  mismatched,
		Expect:       ContainExpectation{MapError: "linkage_mismatch"},
	}
	if r := runContainVector(v); !r.Pass {
		t.Fatalf("expected map_error was not accepted: got=%s note=%s", r.Got, r.Note)
	}
	v.ChildSource = matching
	if r := runContainVector(v); r.Pass {
		t.Fatalf("a mapped pair satisfied a map_error expectation: got=%s note=%s", r.Got, r.Note)
	}

	// A source the profile cannot map at all is the catch-all code.
	v.ChildSource = json.RawMessage(`{"parent_grant_id":"g-1","capabilities":[{"id":""}]}`)
	v.Expect = ContainExpectation{MapError: "mapping_failed"}
	if r := runContainVector(v); !r.Pass {
		t.Fatalf("mapping_failed was not accepted: got=%s note=%s", r.Got, r.Note)
	}
}

// TestLoadContainRequiresOneExpectation pins the loader's presence check: the
// Go bool cannot tell an omitted contains from contains: false, so the raw
// object is checked instead.
func TestLoadContainRequiresOneExpectation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vectors.json")
	body := `[{"id":"ccx-900","kind":"contain-crosswalk","spec_clause":"x","profile":"iicp->clc-v1","parent_source":{},"child_source":{},"expect":{},"derivation":"x"}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadContain(path); err == nil {
		t.Fatal("an expect object with neither contains nor map_error was accepted")
	}
}
