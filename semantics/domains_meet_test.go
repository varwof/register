// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import "testing"

// The declared `quantity` domain meets through object recursion once the values
// are normalized: the narrower normalized value wins, and the unit must match.
func TestQuantityMeetNarrows(t *testing.T) {
	dm := DomainMap{"amount": {Name: "quantity", Unit: "CNY"}}
	normalize := func(g Grant) Grant {
		p, reason := NormalizeForDomains(g.Params, dm)
		if reason != "" {
			t.Fatalf("normalize: %s", reason)
		}
		g.Params = p
		return g
	}
	a := normalize(Grant{ID: "std/payments-v1:transfer", Params: map[string]any{
		"amount": map[string]any{"value": 5000.0, "unit": "CNY", "scale": 2.0},
	}})
	b := normalize(Grant{ID: "std/payments-v1:transfer", Params: map[string]any{
		"amount": map[string]any{"value": 3000.0, "unit": "CNY", "scale": 2.0},
	}})
	eff, err := Intersect(a, b)
	if err != nil {
		t.Fatalf("Intersect: %v", err)
	}
	if got := eff.Params["amount"]; got != 30.0 {
		t.Fatalf("meet amount: got %v, want 30 (3000×10^-2)", got)
	}
	inside := Operation{ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 25.0}}
	if got := Authorize(eff, inside); got.Verdict != VerdictAllow {
		t.Fatalf("inside the meet: got %s/%s", got.Verdict, got.Reason)
	}
	outside := Operation{ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 35.0}}
	if got := Authorize(eff, outside); got.Verdict != VerdictDeny {
		t.Fatalf("above the meet: got %s/%s", got.Verdict, got.Reason)
	}
}

// A chain whose hops use the declared quantity domain authorizes an operation
// inside every hop's normalized bound.
func TestQuantityChain(t *testing.T) {
	dm := DomainMap{"amount": {Name: "quantity", Unit: "CNY"}}
	norm := func(v float64) map[string]any {
		p, reason := NormalizeForDomains(map[string]any{
			"amount": map[string]any{"value": v, "unit": "CNY", "scale": 2.0},
		}, dm)
		if reason != "" {
			t.Fatalf("normalize: %s", reason)
		}
		return p
	}
	root := Grant{ID: "std/payments-v1:transfer", Params: norm(5000)}
	leaf := Grant{ID: "std/payments-v1:transfer", Params: norm(3000)}
	if r := Contains(root, leaf); !r.Contains {
		t.Fatalf("quantity chain containment: %s", r.Reason)
	}
	dec := AuthorizeWithChain([]Grant{root, leaf}, Operation{
		ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 25.0},
	})
	if dec.Verdict != VerdictAllow {
		t.Fatalf("inside the chain: got %s/%s", dec.Verdict, dec.Reason)
	}
	dec = AuthorizeWithChain([]Grant{root, leaf}, Operation{
		ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 35.0},
	})
	if dec.Verdict != VerdictDeny {
		t.Fatalf("above the leaf: got %s/%s", dec.Verdict, dec.Reason)
	}
}
