// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"errors"
	"testing"
)

// R-4: removing a grant that is contained in another grant must not change the
// decision for any operation, because every operation the removed grant
// authorizes is also authorized by its container (any-one-covers, §9).
func TestRedundantGrantRemovalPreservesDecision(t *testing.T) {
	parent := Grant{ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 5000, "currency": []any{"CNY"}}}
	child := Grant{ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 3000, "currency": []any{"CNY"}}}
	if r := Contains(parent, child); !r.Contains {
		t.Fatalf("fixture: child not contained in parent: %s", r.Reason)
	}
	ops := []Operation{
		{ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 2000, "currency": "CNY"}},
		{ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 3000, "currency": "CNY"}},
		{ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 4000, "currency": "CNY"}},
		{ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 6000, "currency": "CNY"}},
	}
	for _, op := range ops {
		with := AuthorizeSet([]Grant{parent, child}, op)
		without := AuthorizeSet([]Grant{parent}, op)
		if with.Verdict != without.Verdict {
			t.Errorf("op %v: removing a contained grant changed %s -> %s", op.Params["amount"], with.Verdict, without.Verdict)
		}
	}

	// Negative control: a grant that is *not* contained is not redundant.
	usd := Grant{ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 3000, "currency": []any{"USD"}}}
	opUSD := Operation{ID: "std/payments-v1:transfer", Params: map[string]any{"amount": 2000, "currency": "USD"}}
	if got := AuthorizeSet([]Grant{parent, usd}, opUSD); got.Verdict == VerdictDeny {
		t.Fatalf("fixture: the USD grant should authorize the USD operation")
	}
	if got := AuthorizeSet([]Grant{parent}, opUSD); got.Verdict != VerdictDeny {
		t.Fatalf("negative control: the USD operation should be denied without the USD grant, got %s", got.Verdict)
	}
}

// R-6: the nesting limit is a boundary, not an implementation detail: exactly
// 32 levels is accepted, one more is refused with invalid_params_size.
func TestParamsNestingBoundary(t *testing.T) {
	nested := func(levels int) map[string]any {
		m := map[string]any{"leaf": 1}
		for i := 1; i < levels; i++ {
			m = map[string]any{"n": m}
		}
		return m
	}
	// §6.2 step 4: objects and arrays count, with the outermost object as level
	// 1; the leaf scalar is not a level.
	if err := ValidateOperationParams(nested(32)); err != nil {
		t.Fatalf("depth 32: got %v, want nil", err)
	}
	if err := ValidateOperationParams(nested(33)); !errors.Is(err, ErrInvalidParamsSize) {
		t.Fatalf("depth 33: got %v, want ErrInvalidParamsSize", err)
	}
}
