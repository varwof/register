// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Decision context — the RATS freshness input.
//
// A CLC decision is a pure function of (grant set, operation): it cannot say
// *when* it was made, and it must not read a clock.  But a verdict without a
// point in time cannot be reused as evidence: "allow" as computed last week is
// not "allow" now.  RFC 9334 (RATS) §10 names the three mechanisms that exist
// for pinning that point in time, and this type carries whichever of them the
// relying party chose:
//
//	§10.1 explicit timekeeping — a synchronized, trustworthy clock; the
//	      appraising entity records the instant and an expiry threshold.
//	§10.2 implicit timekeeping by nonce — an unpredictable nonce the evidence
//	      must echo, which gives a "rough" epoch (signed after the nonce was
//	      generated) without trusting any clock.
//	§10.3 implicit timekeeping by epoch ID — a periodically distributed id the
//	      appraising entity compares against the latest one it received.
//
// The mechanisms combine (RATS §10 "There are three common approaches", and
// protocols may use more than one).  Implementations MUST NOT invent freshness
// from the absence of a context: a missing context is a refusal, not a
// timeless allow (ErrContextMissing).
//
// The core deliberately does not read a clock: Fresh takes `now` from the
// caller, so the same function serves an online enforcement point and an
// offline replay.

package semantics

import (
	"errors"
	"fmt"
	"time"
)

// DecisionContext is the freshness input a relying party pins for one decision.
// At least one mechanism must be present.
type DecisionContext struct {
	// At is the explicit-timekeeping instant (RATS §10.1).  It MUST be UTC: a
	// local-offset instant encodes differently and would change a record's
	// input digest for the same moment in time.
	At time.Time `json:"at,omitempty"`
	// MaxAgeSec bounds how old At may be when the context is checked
	// (RFC 9334 §10: the expiry threshold of the appraisal policy).  Zero means
	// no clock-based bound, which is only sound when another mechanism
	// (nonce/epoch) establishes freshness.
	MaxAgeSec int64 `json:"max_age_sec,omitempty"`
	// Nonce is the appraising entity's unpredictable value that the evidence
	// must echo (RATS §10.2).
	Nonce string `json:"nonce,omitempty"`
	// EpochID is the latest epoch identifier the appraising entity received
	// from its distributor (RATS §10.3).  A pointer so that a legitimate id of
	// zero is distinguishable from "not used".
	EpochID *uint64 `json:"epoch_id,omitempty"`
	// SnapshotDigest identifies the trust/status snapshot the native verifier
	// used (trust anchors, revocation results, epoch distributor state).  A
	// replay that does not bind this cannot show which inputs it re-appraised.
	SnapshotDigest *Digest `json:"snapshot_digest,omitempty"`
}

var (
	// ErrContextMissing means no freshness mechanism was pinned at all (or a
	// caller required a context that was not supplied).  Absence is never an
	// implicit "fresh".
	ErrContextMissing = errors.New("context_missing")
	// ErrContextShape means the context's fields contradict each other (a
	// bound with nothing to bound, a negative bound, an unusable digest).
	ErrContextShape = errors.New("context_shape")
	// ErrContextNotUTC means At carried a non-UTC location; the same instant
	// would otherwise hash differently in different records.
	ErrContextNotUTC = errors.New("context_not_utc")
	// ErrContextFuture means At lies after the checking instant — a
	// future-dated or skewed appraisal, which is never accepted.
	ErrContextFuture = errors.New("context_future")
	// ErrContextStale means At is older than the pinned expiry threshold.
	ErrContextStale = errors.New("context_stale")
	// ErrContextNoClock means freshness was asked of a context that pinned only
	// implicit mechanisms: the nonce/epoch comparison belongs to the native
	// verifier (RATS §10.2/§10.3), so a clock-based check cannot speak for it.
	ErrContextNoClock = errors.New("context_no_clock")
)

// EpochIDOf returns a pointer suitable for DecisionContext.EpochID, so a
// legitimate epoch id of zero is not read as "absent".
func EpochIDOf(v uint64) *uint64 { return &v }

// MaxAge returns the clock-based expiry threshold as a duration (0 = none).
func (c DecisionContext) MaxAge() time.Duration {
	return time.Duration(c.MaxAgeSec) * time.Second
}

// IsZero reports whether the context pins no freshness mechanism at all.
func (c DecisionContext) IsZero() bool {
	return c.At.IsZero() && c.Nonce == "" && c.EpochID == nil
}

// Validate checks that the context is usable: at least one mechanism, no
// contradiction between fields, a UTC instant when one is given, and a
// well-formed snapshot digest.
func (c DecisionContext) Validate() error {
	// Contradictions first: a bound with nothing to bound is a shape error
	// rather than "no context pinned", which is the more useful diagnosis.
	if c.MaxAgeSec < 0 {
		return fmt.Errorf("%w: negative max_age_sec", ErrContextShape)
	}
	if c.MaxAgeSec > 0 && c.At.IsZero() {
		return fmt.Errorf("%w: max_age_sec without at", ErrContextShape)
	}
	if c.IsZero() {
		return ErrContextMissing
	}
	if !c.At.IsZero() && c.At.Location() != time.UTC {
		return fmt.Errorf("%w: at carries location %s", ErrContextNotUTC, c.At.Location())
	}
	if c.SnapshotDigest != nil {
		if c.SnapshotDigest.Alg == "" || len(c.SnapshotDigest.Value) == 0 {
			return fmt.Errorf("%w: incomplete snapshot digest", ErrContextShape)
		}
	}
	if c.Nonce != "" && len(c.Nonce) > maxContextNonceBytes {
		return fmt.Errorf("%w: nonce longer than %d bytes", ErrContextShape, maxContextNonceBytes)
	}
	return nil
}

// maxContextNonceBytes bounds a nonce the same way §6.2 bounds other inputs, so
// a hostile peer cannot inflate the record.
const maxContextNonceBytes = 512

// Fresh reports whether the context's clock mechanism still holds at now.
//
// now is supplied by the caller (the core never reads a clock).  A context that
// pinned only a nonce or an epoch id has no clock claim to check: this returns
// ErrContextNoClock rather than passing, because a clock-based function cannot
// speak for an implicit mechanism — the native verifier must have compared the
// nonce/epoch instead.
func (c DecisionContext) Fresh(now time.Time) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.At.IsZero() {
		return ErrContextNoClock
	}
	if now.Before(c.At) {
		return fmt.Errorf("%w: context at %s, checking instant %s", ErrContextFuture, c.At.Format(time.RFC3339Nano), now.UTC().Format(time.RFC3339Nano))
	}
	if maxAge := c.MaxAge(); maxAge > 0 {
		if age := now.Sub(c.At); age > maxAge {
			return fmt.Errorf("%w: age %s exceeds %s", ErrContextStale, age, maxAge)
		}
	}
	return nil
}

// Digest binds the context so a record can identify exactly which freshness
// input it was decided under.
func (c DecisionContext) Digest() (Digest, error) {
	if err := c.Validate(); err != nil {
		return Digest{}, err
	}
	return DigestOf(c)
}
