// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package symmetryvectors

import (
	"testing"

	"github.com/varwof/register/semantics"
)

// TestSymmetryVectors runs the authorization/evidence symmetry corpus.
func TestSymmetryVectors(t *testing.T) {
	path, err := ResolvePath()
	if err != nil {
		t.Skipf("%v", err)
	}
	vectors, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(vectors) != 50 {
		t.Fatalf("corpus has %d vectors, expected 50", len(vectors))
	}
	failures := 0
	for _, r := range Run(vectors) {
		if r.Pass {
			continue
		}
		failures++
		t.Errorf("%s: %s", r.ID, r.Note)
	}
	if failures == 0 {
		t.Logf("ran %d symmetry vectors", len(vectors))
	}
}

// TestSymmetryIdempotent pins P3/P5 on the pair: evaluating the same
// authorization and evidence inputs twice yields the same result.
func TestSymmetryIdempotent(t *testing.T) {
	path, err := ResolvePath()
	if err != nil {
		t.Skipf("%v", err)
	}
	vectors, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	first := Run(vectors)
	second := Run(vectors)
	for i := range first {
		if first[i].Pass != second[i].Pass || first[i].Note != second[i].Note {
			t.Errorf("%s: second run differs: %v/%q vs %v/%q",
				first[i].ID, first[i].Pass, first[i].Note, second[i].Pass, second[i].Note)
		}
	}
}

// TestMultiGrantOrderIndependent pins P11 on the authorization side: where a
// vector uses independent grants (not a root-first chain), reversing their order
// must not change the decision.
func TestMultiGrantOrderIndependent(t *testing.T) {
	path, err := ResolvePath()
	if err != nil {
		t.Skipf("%v", err)
	}
	vectors, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	checked := 0
	for _, v := range vectors {
		if v.Authorization.Chain || len(v.Authorization.Grants) < 2 {
			continue
		}
		checked++
		rev := v
		rev.Authorization.Grants = make([]semantics.Grant, len(v.Authorization.Grants))
		for i := range v.Authorization.Grants {
			rev.Authorization.Grants[i] = v.Authorization.Grants[len(v.Authorization.Grants)-1-i]
		}
		if got := runOne(rev); !got.Pass {
			t.Errorf("%s: reversed grant order changed the outcome: %s", v.ID, got.Note)
		}
	}
	if checked == 0 {
		t.Skip("no multi-grant vectors in the corpus")
	}
	t.Logf("checked %d multi-grant vectors", checked)
}
