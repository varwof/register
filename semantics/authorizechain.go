// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// AuthorizeWithChain — the fused chain check (CLC §13.11, rev CLC-1.13).
//
// Contains (§13.4) is a declared-set comparison and Authorize (§9) is an
// operation-time decision; a consumer holding a delegation chain often wants
// both in one call.  This function fixes the order and fails closed at each
// step.  It is a CLC-D function: it changes no CLC-A verdict and introduces no
// new core semantics.
//
// Soundness note: constraints are outside containment (§13.4.4, a union axis),
// so authorizing against the leaf grant alone could let an operation pass that
// violates an ancestor's constraints.  The operation is therefore judged
// against Intersect(chain...), which brings every ancestor's params AND
// constraints into force.  For the same reason a chain carrying `param_bounds`
// is refused (Intersect defines no param_bounds intersection, §7) rather than
// having the bound silently dropped.

package semantics

// AuthorizeWithChain checks each adjacent hop with Contains and, if the whole
// chain is contained, authorizes op against Intersect(chain...).
//
// An empty chain denies absent_source.  The first hop whose containment fails
// ends the call with that hop's §13.5 reason code — before op validation.
// An Intersect refusal (no_overlap, empty_bound_denies_class,
// invalid_params_binding) is returned as deny(reason).  Otherwise the
// operation-layer Decision (allow / allow_unresolved / deny with §9 reasons)
// passes through unchanged.
func AuthorizeWithChain(chain []Grant, op Operation) Decision {
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
