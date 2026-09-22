// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// ConstraintUnion — the derived chain-constraint projection (CLC §7.1,
// rev CLC-1.12).
//
// A consumer that has established a delegation chain often needs the chain's
// whole constraint burden without computing an effective grant.  This is
// exactly the constraint projection of Intersect rule 3, exposed as a named
// function.  It is a projection, not a meet: it does not compare identifiers
// or parameters, does not read or validate constraint values, and does not
// check containment (that is Contains, §13).  An empty chain fails closed
// with absent_source (§7 rule 5).

package semantics

// ConstraintUnion returns the normalized union of every constraint string
// carried by the grants in chain — duplicates folded, deterministically
// ordered (lexically sorted) — the same normalization Intersect applies.
// An empty chain returns (nil, ErrAbsentSource).
func ConstraintUnion(chain ...Grant) ([]string, error) {
	if len(chain) == 0 {
		return nil, ErrAbsentSource
	}
	var out []string
	for _, g := range chain {
		out = mergeConstraints(out, g.Constraints)
	}
	return out, nil
}
