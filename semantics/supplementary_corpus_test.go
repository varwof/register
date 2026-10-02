// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The two CLC-1.15 supplementary corpora have no entry in the default vector
// set, so the standalone runners reach them only when CLC_PARAM_BOUNDS_VECTORS
// / CLC_CONSTRAINT_UNION_VECTORS point at them.  These tests put both corpora in
// the ordinary `go test ./...` run.
//
//	* constraint-union-collation-vectors.json — §7.1 UTF-8 byte-order collation.
//	  U+E000 (UTF-8 EE 80 80) against U+1F600 (F0 9F 98 80); a UTF-16 code-unit
//	  comparator reverses them.
//	* param-bounds-equality-vectors.json — §6.5 type-sensitive equality under
//	  param_bounds.

type cuVector struct {
	ID     string   `json:"id"`
	Chain  []Grant  `json:"chain"`
	Expect cuExpect `json:"expect"`
}

type cuExpect struct {
	Union  []string `json:"union"`
	Reason string   `json:"reason,omitempty"`
}

type pbVector struct {
	ID      string     `json:"id"`
	Grant   *Grant     `json:"grant"`
	Request *Operation `json:"request"`
	Expect  pbExpect   `json:"expect"`
}

type pbExpect struct {
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
}

func supplementaryPath(env, name string) string {
	if p := os.Getenv(env); p != "" {
		return p
	}
	return filepath.Join("..", "..", "capability", "data", "_vectors", "clc-v1", name)
}

func loadEnvelope(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("supplementary corpus not found at %s: %v", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

// TestConstraintUnionCollationVectors pins the §7.1 UTF-8 byte-order collation:
// merging the chain must emit normalized constraints ordered octet by octet over
// their UTF-8 encodings, not by UTF-16 code unit.
func TestConstraintUnionCollationVectors(t *testing.T) {
	path := supplementaryPath("CLC_CONSTRAINT_UNION_VECTORS", "constraint-union-collation-vectors.json")
	var vectors []cuVector
	loadEnvelope(t, path, &vectors)

	for _, v := range vectors {
		got, err := ConstraintUnion(v.Chain...)
		if v.Expect.Reason != "" {
			if err == nil || canonicalCode(err.Error()) != canonicalCode(v.Expect.Reason) {
				t.Errorf("%s: want reason %q, got %v", v.ID, v.Expect.Reason, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", v.ID, err)
			continue
		}
		if !slices.Equal(got, v.Expect.Union) {
			t.Errorf("%s: want %q, got %q", v.ID, v.Expect.Union, got)
		}
	}
}

// TestParamBoundsEqualityVectors runs the §6.5 type-sensitive equality corpus
// through Entails, so the reference engine exercises it in `go test`.
func TestParamBoundsEqualityVectors(t *testing.T) {
	path := supplementaryPath("CLC_PARAM_BOUNDS_VECTORS", "param-bounds-equality-vectors.json")
	var vectors []pbVector
	loadEnvelope(t, path, &vectors)

	for _, v := range vectors {
		grant := Grant{}
		if v.Grant != nil {
			grant = *v.Grant
		}
		op := Operation{}
		if v.Request != nil {
			op = *v.Request
		}
		res := Entails(grant, op)
		got, reason := "deny", canonicalCode(res.Reason)
		if res.Entails {
			got, reason = "allow", ""
		}
		if got != v.Expect.Verdict || reason != canonicalCode(v.Expect.Reason) {
			t.Errorf("%s: want %s/%s, got %s/%s", v.ID, v.Expect.Verdict,
				canonicalCode(v.Expect.Reason), got, reason)
		}
	}
}
