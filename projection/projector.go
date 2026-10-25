// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/varwof/register/semantics"
)

// ProjectedView is the minimal view the CLC decision layer needs from an
// external evidence document.
type ProjectedView struct {
	Action      *semantics.ActionId
	Facts       []semantics.EvidenceFact
	Requirement *semantics.Requirement
	// SourceRequirementDigest is the JCS SHA-256 of the complete source
	// requirement as received, before any projection.  It is report evidence
	// and is never a member of the CLC Requirement or Satisfaction objects.
	SourceRequirementDigest *semantics.Digest
	// ProjectedRequirementDigest is the CLC requirement digest over the final,
	// validated CLC-REQUIREMENT-v1 object after all rewriting.
	ProjectedRequirementDigest *semantics.Digest
	Residuals                  []string
	RequiredNativeChecks       []string
	Meta                       map[string]string
}

// NativeUnavailability records a native input that could not be obtained,
// refreshed or verified.  It therefore contributes no eligible Fact for Type.
// The reason is report evidence only: it is never a Fact, never a satisfied
// residual and never the authorization-only "unresolved" verdict.  It remains
// visible even when a sibling OR branch satisfies the projected requirement.
type NativeUnavailability struct {
	// Type is the native evidence role (or the mapped CLC role) the input
	// would have filled.
	Type string `json:"type"`
	// Reason is the stable native reason the input is unavailable.
	Reason string `json:"reason"`
}

// Context carries the pins a projection needs.
type Context struct {
	Now       time.Time
	Initiator string
	Executor  string

	// RoleMap bridges a foreign role/component identifier to the CLC evidence
	// role facts are typed by.  A mapping is never guessed: the relying party
	// pins it (the same way an Action-Mapping Profile is pinned).  An entry
	// that is absent leaves the foreign identifier in place and surfaces a
	// residual instead of silently inventing a bridge.
	RoleMap map[string]string
}

// Projector recognises and projects one external evidence format.
type Projector interface {
	ID() string
	Match(raw []byte) bool
	Project(raw []byte, ctx Context) (ProjectedView, error)
}

// sourceRequirementDigest returns the SHA-256 of the JCS encoding of the
// complete source requirement.  Numbers are decoded as json.Number so the
// canonical bytes do not depend on float64 round-tripping.  Strict JSON and
// duplicate-member rejection are the caller's responsibility.
func sourceRequirementDigest(raw []byte) (semantics.Digest, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var source any
	if err := dec.Decode(&source); err != nil {
		return semantics.Digest{}, fmt.Errorf("decode source requirement: %w", err)
	}
	digest, err := semantics.DigestOf(source)
	if err != nil {
		return semantics.Digest{}, fmt.Errorf("digest source requirement: %w", err)
	}
	return digest, nil
}
