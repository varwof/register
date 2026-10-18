// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Package ocmp evaluates an Offline Capability Manifest against the profile's
// normative rules R2–R7 (docs/offline-capability-manifest-profile-v0.md §3).
//
// The profile is a fail-closed wrapper around a CLC grant decision: every rule
// here denies with a stable code and never raises.  It is deliberately separate
// from CLC core semantics (OCMP §8); the vectors in
// data/_vectors/clc-v1/offline-vectors.json exercise this layer.
package ocmp

// Status is the revocation snapshot.
type Status struct {
	Present      bool
	Verified     bool
	AsOf         int64
	ValidUntil   int64
	Version      int64
	LastAccepted int64
}

// Inputs are the local, offline inputs the profile evaluates.  Nothing here is
// fetched: R1 requires evaluation to depend only on these and the request.
type Inputs struct {
	GrantCovers bool
	TrustAnchor bool
	LocalPolicy bool
	Status      Status

	CredentialExpired bool
	Revoked           bool

	ReplayEnabled bool
	Counter       int64
	LastConsumed  int64

	RequiredFact  bool
	FactAvailable bool

	TrustedTime    int64
	ClockOffset    int64
	ClockTolerance int64
}

// Result is a deny with a stable reason, or allow.
type Result struct {
	Verdict string
	Reason  string
}

func deny(reason string) Result { return Result{Verdict: "deny", Reason: reason} }

// Evaluate applies R2–R7 in a fixed order (missing inputs before derived ones).
func Evaluate(in Inputs) Result {
	// R2: missing MUST inputs.
	if !in.GrantCovers {
		return deny("capability_not_authorized")
	}
	if !in.TrustAnchor {
		return deny("trust_anchor_missing")
	}
	if !in.LocalPolicy {
		return deny("local_policy_missing")
	}
	if !in.Status.Present || !in.Status.Verified {
		return deny("status_snapshot_missing")
	}
	// R3: snapshot window and monotonic version.
	if in.TrustedTime < in.Status.AsOf || in.TrustedTime > in.Status.ValidUntil {
		return deny("status_snapshot_expired")
	}
	if in.Status.Version < in.Status.LastAccepted {
		return deny("status_snapshot_rollback")
	}
	// R4: lifetime and revocation.
	if in.Revoked {
		return deny("revoked")
	}
	if in.CredentialExpired {
		return deny("capability_not_authorized")
	}
	// R5: counter/nonce consumption.
	if in.ReplayEnabled {
		if in.Counter == in.LastConsumed {
			return deny("replay_detected")
		}
		if in.Counter < in.LastConsumed {
			return deny("replay_state_invalid")
		}
	}
	// R6: required local facts.
	if in.RequiredFact && !in.FactAvailable {
		return deny("fact_unavailable")
	}
	// R7: time source offset.
	if in.ClockOffset > in.ClockTolerance {
		return deny("clock_unsynchronized")
	}
	return Result{Verdict: "allow"}
}
