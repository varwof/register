// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"encoding/hex"
	"fmt"
	"time"
)

// digestAlg is the only digest algorithm the report revision defines.  A
// different name is a refusal, never computed with a fallback.
const digestAlg = "sha-256"

// Digest is a typed content digest in its canonical report form:
//
//	sha-256:<64 lowercase hex>
//
// The canonical form is pinned because the report is signed over its JCS
// encoding; accepting two spellings of one digest would change the bytes two
// implementations sign.  Native artifacts may use any encoding internally; the
// profile converts to this form when it fills the report.
type Digest string

// ParseDigest validates raw and returns it as a Digest.
func ParseDigest(raw string) (Digest, error) {
	d := Digest(raw)
	if err := d.Validate(); err != nil {
		return "", err
	}
	return d, nil
}

// DigestFromBytes renders a raw SHA-256 sum in canonical form.
func DigestFromBytes(sum []byte) Digest {
	return Digest(digestAlg + ":" + hex.EncodeToString(sum))
}

// Validate checks the algorithm tag and the hex length.
func (d Digest) Validate() error {
	s := string(d)
	if len(s) != len(digestAlg)+1+64 {
		return fmt.Errorf("digest %q is not %s:<64 hex>", s, digestAlg)
	}
	if s[:len(digestAlg)+1] != digestAlg+":" {
		return fmt.Errorf("digest %q does not name %s", s, digestAlg)
	}
	for i := len(digestAlg) + 1; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("digest %q is not lowercase hex", s)
		}
	}
	return nil
}

// Empty reports whether the digest is absent.
func (d Digest) Empty() bool { return d == "" }

// FreshnessVerdict is the closed set of native freshness decisions.
type FreshnessVerdict string

const (
	// FreshnessFresh means the native profile evaluated a snapshot that is
	// current under its own freshness rule.
	FreshnessFresh FreshnessVerdict = "fresh"
	// FreshnessCached means the profile accepted a cached snapshot within the
	// profile's freshness window.  CLC never refreshes it.
	FreshnessCached FreshnessVerdict = "cached"
	// FreshnessStale means the snapshot was outside the window and the check
	// therefore failed.
	FreshnessStale FreshnessVerdict = "stale"
)

// Valid reports whether f is one of the three closed verdicts.
func (f FreshnessVerdict) Valid() bool {
	switch f {
	case FreshnessFresh, FreshnessCached, FreshnessStale:
		return true
	}
	return false
}

// FreshnessDecision is the typed freshness input attached to a native check
// result.  The snapshot fields are optional because not every check reads a
// snapshot; the verdict is mandatory whenever the field is present.
type FreshnessDecision struct {
	Verdict FreshnessVerdict `json:"verdict"`
	// CheckedAt is when the snapshot was produced (not when it was read).
	CheckedAt *time.Time `json:"checkedAt,omitempty"`
	// ValidUntil is the profile's own validity bound for the snapshot.
	ValidUntil *time.Time `json:"validUntil,omitempty"`
	// SnapshotGeneration is the native generation/epoch of the snapshot, used
	// to detect rollback once the profile compares it against accepted state.
	SnapshotGeneration int64 `json:"snapshotGeneration,omitempty"`
}

// IsZero reports whether no decision was recorded.
func (f FreshnessDecision) IsZero() bool { return f.Verdict == "" }

// Validate checks the closed verdict and the optional bounds.
func (f FreshnessDecision) Validate() error {
	if !f.Verdict.Valid() {
		return fmt.Errorf("freshness verdict %q is not fresh|cached|stale", f.Verdict)
	}
	if f.CheckedAt != nil && f.ValidUntil != nil && !f.ValidUntil.After(*f.CheckedAt) {
		return fmt.Errorf("freshness validUntil %s is not after checkedAt %s",
			f.ValidUntil.Format(time.RFC3339), f.CheckedAt.Format(time.RFC3339))
	}
	return nil
}
