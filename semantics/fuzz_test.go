// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

// The JSON number is a semantic type; a Go int, int64 or float64 is only an
// encoding of it (rev CLC-1.15).  These targets pin the two properties that
// makes observable, and neither is expressible in the JSON conformance corpus
// because every JSON number decodes to float64:
//
//	1. representation invariance — the same magnitude decides the same way
//	   whatever Go type carries it;
//	2. JSON type sensitivity — a string, bool or null never satisfies a number
//	   grant, and a number never satisfies a string or bool grant.
//
// Run the seeds with `go test ./semantics/ -run Fuzz`; fuzz with
// `go test ./semantics/ -fuzz FuzzValueSubset -fuzztime 30s`.

// fuzzNumber keeps |v| below 2^52 so float64 carries it exactly and the
// invariant below cannot fail through a representation limit rather than
// through a comparison bug.
func fuzzNumber(u uint64) float64 {
	return float64(int64(u%(1<<52))) - (1 << 51)
}

func FuzzValueSubsetNumericRepresentation(f *testing.F) {
	for _, s := range []struct {
		grant, op int64
	}{
		{100, 100}, {100, 99}, {100, 101}, {100, 0}, {0, 0}, {-5, -5}, {1, 0},
	} {
		f.Add(uint64(s.grant), uint64(s.op))
	}
	f.Fuzz(func(t *testing.T, g, o uint64) {
		grant, op := fuzzNumber(g), fuzzNumber(o)
		// int64 carries both magnitudes exactly (|v| < 2^52), so every pair
		// below compares the *same* two JSON numbers in different Go types.
		grantI, opI := int64(grant), int64(op)

		wantOK, wantReason := valueSubset(op, grant)
		pairs := [][2]any{
			{op, grant}, {opI, grantI}, {opI, grant}, {op, grantI},
			{int(opI), int(grantI)},
		}
		// Narrower types only when the magnitude survives the conversion.
		if op >= -(1<<31) && op <= 1<<31 && grant >= -(1<<31) && grant <= 1<<31 {
			pairs = append(pairs, [2]any{int32(opI), int32(grantI)},
				[2]any{float32(op), float32(grant)})
		}
		for _, pair := range pairs {
			gotOK, gotReason := valueSubset(pair[0], pair[1])
			if gotOK != wantOK {
				t.Errorf("representation changed the decision: %v vs %v under %v <= %v (ok=%v/%v vs %v/%v)",
					pair[0], pair[1], op, grant, gotOK, gotReason, wantOK, wantReason)
			}
		}

		// (2) A numeric grant is an upper bound: op <= grant allows.
		if op <= grant && !wantOK {
			t.Errorf("op %v <= grant %v denied: %q", op, grant, wantReason)
		}
		if op > grant && wantOK {
			t.Errorf("op %v > grant %v allowed", op, grant)
		}
	})
}

func FuzzValueSubsetCrossType(f *testing.F) {
	f.Add(uint64(50), "50", true)
	f.Add(uint64(1), "1", false)
	f.Add(uint64(0), "", true)
	f.Fuzz(func(t *testing.T, n uint64, s string, flag bool) {
		grant := fuzzNumber(n)

		// A string, bool, null, array or object is never the number it
		// spells.  Null carries its own §6.2 code; the rest fail closed as
		// an exceeded grant.
		for _, c := range []struct {
			op     any
			reason string
		}{
			{s, ErrParamsExceedGrant.Error()},
			{flag, ErrParamsExceedGrant.Error()},
			{[]any{s}, ErrParamsExceedGrant.Error()},
			{map[string]any{"k": flag}, ErrParamsExceedGrant.Error()},
			{nil, ErrInvalidParamsNull.Error()},
		} {
			if ok, reason := valueSubset(c.op, grant); ok {
				t.Errorf("non-number op %#v satisfied the numeric grant %v", c.op, grant)
			} else if reason != c.reason {
				t.Errorf("op %#v vs numeric grant %v: reason %q, want %q",
					c.op, grant, reason, c.reason)
			}
		}

		// And a number never satisfies a string or bool grant.
		for _, g := range []any{s, flag} {
			if ok, _ := valueSubset(grant, g); ok {
				t.Errorf("number %v satisfied the non-numeric grant %#v", grant, g)
			}
		}
	})
}

// FuzzAuthorizeAgreesWithEntails pins the cross-layer contract: whatever the
// params value layer entails, the decision function must authorize, and a
// denied entailment must not be authorized either.
func FuzzAuthorizeAgreesWithEntails(f *testing.F) {
	f.Add(uint64(100), uint64(50), "n")
	f.Add(uint64(10), uint64(50), "k")
	f.Fuzz(func(t *testing.T, g, o uint64, key string) {
		if key == "" {
			return
		}
		grant := Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{key: fuzzNumber(g)}}
		op := Operation{ID: "std/database-v1:query:SELECT", Params: map[string]any{key: fuzzNumber(o)}}

		entailed := Entails(grant, op).Entails
		decision := Authorize(grant, op)
		if entailed && decision.Verdict != VerdictAllow {
			t.Errorf("entailed %v <= %v but authorize returned %q (%q)",
				op.Params[key], grant.Params[key], decision.Verdict, decision.Reason)
		}
		if !entailed && decision.Verdict == VerdictAllow {
			t.Errorf("not entailed %v <= %v but authorize allowed",
				op.Params[key], grant.Params[key])
		}
	})
}
