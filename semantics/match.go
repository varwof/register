// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Match — evidence binding on the instance level (§6.4, §4.2/§4.3).
//
// Entailment answers "does this grant cover this operation class"; Match answers
// "is this evidence about *this exact action*".  The two are different questions,
// and an artifact can pass its own native verification while being about
// something else entirely — which is why §6.4 makes Match its own step and why
// §4.2 fixes the material projection normatively:
//
//   - the action type declares a **material field set**; only those fields enter
//     the digest, and undeclared fields carry no action identity (they are
//     excluded, not an error);
//   - a declared field that is missing makes the action **non-matchable**:
//     coverage is never inferred, defaulted or repaired (§4.2);
//   - the digest is taken over the JCS canonical serialization of the material
//     projection, and the suite names the algorithm (§4.3), e.g.
//     `clc-action:1:payment.release.1:jcs-sha256:<b64url>`.
//
// The identifier is the language's own projection identity, not a CAID.  A CAID
// covers the complete Action Object under its own suite registry, and identifies
// the action object, not an occurrence; this projection covers only the declared
// material set.  The two are related by a relying-party-pinned Action-Mapping
// Profile, never by assuming they are the same string.
//
// Matching is content correlation only: it validates no signature and
// authorizes nothing.  Comparison across suites or action types is not a
// "different action", it is *undecidable* here — it needs a relying-party-pinned
// mapping profile, so it reports INDETERMINATE rather than guessing.

package semantics

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ActionIdSuite names a canonicalization+digest suite.  The set is closed.
type ActionIdSuite string

const (
	// SuiteJCSSHA256 is JCS canonicalization over SHA-256; it is the only suite
	// defined in v1.  A name outside the set is a refusal, never a computation.
	SuiteJCSSHA256 ActionIdSuite = "jcs-sha256"
)

// actionIdPrefix is the version tag of the identifier string form.
const actionIdPrefix = "clc-action:1"

var (
	// ErrActionShape means the action, its type definition, or an identifier
	// string is malformed.
	ErrActionShape = errors.New("action_shape")
	// ErrActionSuite means an unknown canonicalization+digest suite was named.
	ErrActionSuite = errors.New("action_suite")
	// ErrActionNotMatchable means a declared material field is absent: the action
	// cannot be identified, so it cannot match anything (fail-closed, never
	// "assume it was the same").
	ErrActionNotMatchable = errors.New("action_not_matchable")
	// ErrActionProjectionLossy means a mapping profile dropped or altered
	// material content; a lossy projection must never establish equivalence.
	ErrActionProjectionLossy = errors.New("action_projection_lossy")
)

// ActionTypeDefinition is the declared material field set of one action type.
// The relying party pins the definition source (§6.4 step 3).
type ActionTypeDefinition struct {
	Type string `json:"type"`
	// MaterialFields are the fields that make up the action's identity.
	// Required and optional-but-included fields are both listed here: the
	// projection includes exactly this set.
	MaterialFields []string `json:"material_fields"`
}

// Validate checks the definition itself.
func (d ActionTypeDefinition) Validate() error {
	if d.Type == "" {
		return fmt.Errorf("%w: action type required", ErrActionShape)
	}
	if len(d.MaterialFields) == 0 {
		return fmt.Errorf("%w: action type %s declares no material fields", ErrActionShape, d.Type)
	}
	seen := make(map[string]bool, len(d.MaterialFields))
	for _, f := range d.MaterialFields {
		if f == "" {
			return fmt.Errorf("%w: empty material field name", ErrActionShape)
		}
		if seen[f] {
			return fmt.Errorf("%w: duplicate material field %q", ErrActionShape, f)
		}
		seen[f] = true
	}
	return nil
}

// ActionId is a typed, suite-tagged content identity for the material content of
// one action.  It is not an occurrence identifier: an occurrence needs a
// discriminator supplied by the effect boundary (§6.4).
type ActionId struct {
	Type   string
	Suite  ActionIdSuite
	Digest Digest
}

// String renders the identifier form: clc-action:1:<type>:<suite>:<digest-b64url>.
func (a ActionId) String() string {
	return fmt.Sprintf("%s:%s:%s:%s", actionIdPrefix, a.Type, a.Suite,
		base64.RawURLEncoding.EncodeToString(a.Digest.Value))
}

// Validate checks the identifier's own shape.
func (a ActionId) Validate() error {
	if a.Type == "" {
		return fmt.Errorf("%w: action type required", ErrActionShape)
	}
	if !a.Suite.valid() {
		return fmt.Errorf("%w: %q", ErrActionSuite, a.Suite)
	}
	if a.Digest.Alg == "" || len(a.Digest.Value) == 0 {
		return fmt.Errorf("%w: action digest required", ErrActionShape)
	}
	// The digest length is suite-pinned (audit 2026-09-16, R15): for
	// jcs-sha256 the value must be exactly 32 bytes.  A length-mismatched
	// digest would change identity semantics while claiming the suite name.
	if a.Suite == SuiteJCSSHA256 && len(a.Digest.Value) != sha256.Size {
		return fmt.Errorf("%w: %s digest must be %d bytes, got %d", ErrActionShape, a.Suite, sha256.Size, len(a.Digest.Value))
	}
	return nil
}

func (s ActionIdSuite) valid() bool {
	switch s {
	case SuiteJCSSHA256:
		return true
	}
	return false
}

// ParseActionId parses the string form.
func ParseActionId(s string) (ActionId, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 5 || parts[0] != "clc-action" || parts[1] != "1" {
		return ActionId{}, fmt.Errorf("%w: %q", ErrActionShape, s)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return ActionId{}, fmt.Errorf("%w: digest is not base64url: %q", ErrActionShape, s)
	}
	id := ActionId{Type: parts[2], Suite: ActionIdSuite(parts[3]), Digest: Digest{Alg: digestAlgOf(ActionIdSuite(parts[3])), Value: raw}}
	if err := id.Validate(); err != nil {
		return ActionId{}, err
	}
	return id, nil
}

func digestAlgOf(suite ActionIdSuite) string {
	if suite == SuiteJCSSHA256 {
		return DigestAlgSHA256
	}
	return ""
}

// ComputeActionID projects the action onto the type's material field set and
// returns its typed identity.  A declared field that is absent makes the action
// non-matchable.
func ComputeActionID(def ActionTypeDefinition, suite ActionIdSuite, action map[string]any) (ActionId, error) {
	if err := def.Validate(); err != nil {
		return ActionId{}, err
	}
	if !suite.valid() {
		return ActionId{}, fmt.Errorf("%w: %q", ErrActionSuite, suite)
	}
	projection := make(map[string]any, len(def.MaterialFields))
	for _, field := range def.MaterialFields {
		value, ok := action[field]
		if !ok {
			return ActionId{}, fmt.Errorf("%w: material field %q absent for %s", ErrActionNotMatchable, field, def.Type)
		}
		projection[field] = value
	}
	canonical, err := CanonicalJSON(projection)
	if err != nil {
		return ActionId{}, err
	}
	sum := hashFor(suite, canonical)
	return ActionId{Type: def.Type, Suite: suite, Digest: Digest{Alg: digestAlgOf(suite), Value: sum}}, nil
}

// MaterialProjection returns the map that ComputeActionID hashes, so a caller can
// disclose exactly what entered the identity (and nothing else did).
func MaterialProjection(def ActionTypeDefinition, action map[string]any) (map[string]any, error) {
	if err := def.Validate(); err != nil {
		return nil, err
	}
	out := make(map[string]any, len(def.MaterialFields))
	for _, field := range def.MaterialFields {
		value, ok := action[field]
		if !ok {
			return nil, fmt.Errorf("%w: material field %q absent for %s", ErrActionNotMatchable, field, def.Type)
		}
		out[field] = value
	}
	return out, nil
}

// MaterialFieldDigest returns the per-field digests of the material projection
// in a deterministic order — what an Action-Mapping Profile may project without
// losing identity.
func MaterialFieldDigest(def ActionTypeDefinition, action map[string]any) ([]string, error) {
	projection, err := MaterialProjection(def, action)
	if err != nil {
		return nil, err
	}
	fields := make([]string, 0, len(projection))
	for field := range projection {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		canonical, err := CanonicalJSON(projection[field])
		if err != nil {
			return nil, err
		}
		out = append(out, field+":"+hex.EncodeToString(hashFor(SuiteJCSSHA256, canonical)))
	}
	return out, nil
}

// MatchVerdict is §6.4's decision about two action identities.
type MatchVerdict string

const (
	// MatchExact means the evidence is about exactly this action.
	MatchExact MatchVerdict = "MATCH"
	// MatchNotEquivalent means both identities are comparable and differ.
	MatchNotEquivalent MatchVerdict = "NOT_EQUIVALENT"
	// MatchIndeterminate means the comparison cannot be made here (different
	// suite or action type): it needs a pinned mapping profile, and an
	// indeterminate comparison is never a match.
	MatchIndeterminate MatchVerdict = "INDETERMINATE"
)

// Match compares a natively verified evidence identity with the executor's
// observed identity.  It never guesses: anything it cannot decide is
// INDETERMINATE, which consumers must treat as "not matched" (fail-closed).
func Match(observed, evidence ActionId) MatchVerdict {
	if observed.Validate() != nil || evidence.Validate() != nil {
		return MatchIndeterminate
	}
	if observed.Type != evidence.Type || observed.Suite != evidence.Suite {
		// Cross-type or cross-suite comparison is a mapping problem, not an
		// inequality.
		return MatchIndeterminate
	}
	if observed.Digest.Equal(evidence.Digest) {
		return MatchExact
	}
	return MatchNotEquivalent
}

// ActionMappingProfile names a projection by its content hash and is pinned by
// the relying party (§6.4).  The Canonical Action Identifier draft describes the
// constructs the bridge to and from a CAID, which covers the complete Action
// Object rather than this projection; the draft is cited here, not reproduced.  A profile
// without a usable digest cannot be pinned, and an unpinned profile establishes
// nothing.
type ActionMappingProfile struct {
	ID     string `json:"id"`
	Digest Digest `json:"digest"`
}

// Pinned reports whether the profile is usable as a relying-party pin.
func (p ActionMappingProfile) Pinned() bool {
	return p.ID != "" && p.Digest.Alg != "" && len(p.Digest.Value) > 0
}

// ActionProjector projects one natively verified action identity into the
// expected action type under a profile.  It belongs to the native verifier: this
// package does not parse foreign formats.
type ActionProjector func(profile ActionMappingProfile, in ActionId) (ActionId, error)

// MapAndMatch applies a pinned profile and compares the projection with the
// expected identity.  Every failure mode — unpinned profile, projector error, or
// a projection that changes material content — is INDETERMINATE, never MATCH.
func MapAndMatch(profile ActionMappingProfile, projector ActionProjector, evidence, expected ActionId) MatchVerdict {
	if !profile.Pinned() || projector == nil {
		return MatchIndeterminate
	}
	projected, err := projector(profile, evidence)
	if err != nil {
		return MatchIndeterminate
	}
	if projected.Type != expected.Type || projected.Suite != expected.Suite {
		return MatchIndeterminate
	}
	return Match(expected, projected)
}

func hashFor(suite ActionIdSuite, canonical []byte) []byte {
	sum := sha256.Sum256(canonical)
	return sum[:]
}
