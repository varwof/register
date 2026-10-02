// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestAuthorizeWithChainDecomposition pins the §13.11 claim that the fused
// chain check is exactly its three public steps, in order:
//
//	gate:    for each adjacent pair, Contains(chain[i], chain[i+1])
//	then:    effective, err := Intersect(chain...)
//	then:    Authorize(effective, op)
//
// It recomputes the expected decision from those public functions alone and
// requires AuthorizeWithChain to agree, so a change to the fused path that
// stops matching its own decomposition is caught.  The gate runs before op
// validation, so a broken chain reports the hop's §13.5 code even when the
// operation is separately invalid.
func TestAuthorizeWithChainDecomposition(t *testing.T) {
	path := os.Getenv("CLC_AUTHORIZE_CHAIN_VECTORS")
	if path == "" {
		path = filepath.Join("..", "..", "capability", "data", "_vectors", "clc-d", "authorize-chain-vectors.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("chain corpus not found at %s: %v", path, err)
	}

	var vectors []struct {
		ID      string     `json:"id"`
		Chain   []Grant    `json:"chain"`
		Request *Operation `json:"request"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	for _, v := range vectors {
		op := Operation{}
		if v.Request != nil {
			op = *v.Request
		}

		fused := AuthorizeWithChain(v.Chain, op)
		want := decomposeChain(v.Chain, op)

		if fused.Verdict != want.Verdict || canonicalCode(fused.Reason) != canonicalCode(want.Reason) {
			t.Errorf("%s: fused=%s/%s, decomposed=%s/%s", v.ID,
				fused.Verdict, canonicalCode(fused.Reason),
				want.Verdict, canonicalCode(want.Reason))
		}
	}

	// The two-grant form is the degenerate case: one hop, so a passing gate
	// makes the fused verdict the CLC-A verdict of Intersect(parent, child).
	for _, v := range vectors {
		if len(v.Chain) != 2 {
			continue
		}
		op := Operation{}
		if v.Request != nil {
			op = *v.Request
		}
		fused := AuthorizeWithChain(v.Chain, op)
		if hop := Contains(v.Chain[0], v.Chain[1]); !hop.Contains {
			if canonicalCode(fused.Reason) != canonicalCode(hop.Reason) {
				t.Errorf("%s: broken hop fused=%s want=%s", v.ID, canonicalCode(fused.Reason), canonicalCode(hop.Reason))
			}
			continue
		}
		eff, err := Intersect(v.Chain...)
		if err != nil {
			t.Fatalf("%s: Intersect on a passing hop: %v", v.ID, err)
		}
		want := Authorize(eff, op)
		if fused.Verdict != want.Verdict || canonicalCode(fused.Reason) != canonicalCode(want.Reason) {
			t.Errorf("%s: two-grant fused=%s/%s, Intersect+Authorize=%s/%s", v.ID,
				fused.Verdict, canonicalCode(fused.Reason), want.Verdict, canonicalCode(want.Reason))
		}
	}
}

// decomposeChain is the §13.11 algorithm expressed over the public API.
func decomposeChain(chain []Grant, op Operation) Decision {
	if len(chain) == 0 {
		return Decision{Verdict: VerdictDeny, Reason: ErrAbsentSource.Error()}
	}
	for i := 0; i+1 < len(chain); i++ {
		if r := Contains(chain[i], chain[i+1]); !r.Contains {
			return Decision{Verdict: VerdictDeny, Reason: r.Reason}
		}
	}
	effective, err := Intersect(chain...)
	if err != nil {
		return Decision{Verdict: VerdictDeny, Reason: err.Error()}
	}
	return Authorize(effective, op)
}

// TestAuthorizeWithChainGatePrecedesOpValidation pins the ordering: a broken
// hop is reported before the operation is validated, so a chain whose gate
// fails never reports a layer-1 operation error.
func TestAuthorizeWithChainGatePrecedesOpValidation(t *testing.T) {
	parent := Grant{ID: "std/database-v1:query:*"}
	child := Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": 500}}
	widening := Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": 100}}

	d := AuthorizeWithChain([]Grant{parent, widening, child}, Operation{})
	if d.Verdict != VerdictDeny || canonicalCode(d.Reason) != ErrParamsNotNarrower.Error() {
		t.Fatalf("broken hop should precede op validation: got %s/%s", d.Verdict, canonicalCode(d.Reason))
	}
}
