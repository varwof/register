// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Package schemeadmin implements the authority-bounded scheme publication
// surface described in
// analysis/2026-10-22-authority-bounded-capability-publication-architecture.md.
//
// The package defines two immutable artifacts — CLC-SCHEME-PACKAGE-v1 and
// CLC-SCHEME-TRANSITION-v1 — and a deployer-side confirmation path that
// recomputes authority from explicit inputs.  It adds no CLC grammar and no CLC
// verdict: authorization is delegated to the semantics package through the
// CLC-1.19 declared-domain relations (`ContainsWithDomains`,
// `AuthorizeSetWithDomains`).
//
// Deliberate non-features:
//
//   - no trusted `authorized`, `verified` or `approved` member is read from any
//     artifact; both artifacts are closed objects, so such a member is a shape
//     error rather than a claim;
//   - `scheme:verify` does not exist, because verification is unprivileged;
//   - nothing is deleted. Revocation creates a tombstone and a revoked digest
//     stays revoked for every later generation;
//   - `scheme:root-rotate` never accepts a key that is only in the proposed next
//     root. It must be authorized by the current root and it must satisfy the
//     separately configured next-root threshold.
package schemeadmin

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/varwof/register/internal/jsonstrict"
	"github.com/varwof/register/semantics"
)

const (
	// SchemeID is the provisional project-local administration scheme name.
	// It is not a registered IETF or CLC namespace.
	SchemeID = "varwof/scheme-admin-v1"

	// PackageVersion is the artifact version of a scheme package.
	PackageVersion = "CLC-SCHEME-PACKAGE-v1"
	// TransitionVersion is the artifact version of a scheme transition.
	TransitionVersion = "CLC-SCHEME-TRANSITION-v1"
	// DeclarationVersion is the CLC-1.19 scheme declaration version.
	DeclarationVersion = "CLC-SCHEME-v1"

	// VerdictAccept and VerdictReject are the only confirmation outcomes.
	VerdictAccept = "accept"
	VerdictReject = "reject"
)

// Administration capabilities.  `scheme:verify` is intentionally absent: any
// party may verify schemas, digests and compatibility, and a signed result is
// governance evidence only under an explicit approval profile.
const (
	CapCreate     = "scheme:create"
	CapUpdate     = "scheme:update"
	CapRevoke     = "scheme:revoke"
	CapDelegate   = "scheme:delegate"
	CapRootRotate = "scheme:root-rotate"
	CapApprove    = "scheme:approve"
)

// Transition actions.  These are the four actions a transition artifact may
// name; delegation is a grant relation, not a package transition.
const (
	ActionCreate     = "create"
	ActionUpdate     = "update"
	ActionRevoke     = "revoke"
	ActionRootRotate = "root-rotate"
)

// Change classes, coarsest last.
const (
	ChangePatch = "patch"
	ChangeMinor = "minor"
	ChangeMajor = "major"
)

// Stable failure codes.  A confirmation returns at most one of these; the
// detail string carries the underlying CLC reason where one exists.
const (
	CodePackageShape               = "package_shape"
	CodePackageDigestMismatch      = "package_digest_mismatch"
	CodeDeclarationInvalid         = "declaration_invalid"
	CodeTransitionShape            = "transition_shape"
	CodeTransitionDigestMismatch   = "transition_digest_mismatch"
	CodePackageTransitionMismatch  = "package_transition_mismatch"
	CodeSignatureMissing           = "signature_missing"
	CodeSignatureInvalid           = "signature_invalid"
	CodeSignatureChain             = "signature_chain"
	CodeSignatureNoAIC             = "signature_no_aic"
	CodeTransitionSignatureMissing = "transition_signature_missing"
	CodeTransitionSignatureInvalid = "transition_signature_invalid"
	CodePublisherMismatch          = "publisher_mismatch"
	CodePublisherKeyBinding        = "publisher_key_binding"
	CodeAuthorityNoGrant           = "authority_no_grant"
	CodeAuthorityNotContained      = "authority_not_contained"
	CodeAuthorityNotAuthorized     = "authority_not_authorized"
	CodeNamespaceOutsidePolicy     = "namespace_outside_policy"
	CodeNamespaceMismatch          = "namespace_mismatch"
	CodeCLCSupported               = "clc_revision_unsupported"
	CodeMajorExceedsLimit          = "major_exceeds_limit"
	CodeChangeClassInvalid         = "change_class_invalid"
	CodeCreateShape                = "create_shape"
	CodeStateNotEmpty              = "state_not_empty"
	CodeStateShape                 = "state_shape"
	CodeStateUnverified            = "state_unverified"
	CodeStateGeneration            = "state_generation_mismatch"
	CodeStateDigest                = "state_digest_mismatch"
	CodeGenerationRollback         = "generation_rollback"
	CodeGenerationFork             = "generation_fork"
	CodePackageRevoked             = "package_revoked"
	CodeRevocationInvalid          = "revocation_invalid"
	CodePackageExpired             = "package_expired"
	CodePackageStale               = "package_stale"
	CodeApprovalInsufficient       = "approval_insufficient"
	CodeApprovalInvalid            = "approval_invalid"
	CodeRootNoCurrentRoot          = "root_rotate_no_current_root"
	CodeRootSelfAuthorized         = "root_rotate_self_authorized"
	CodeRootPolicyMismatch         = "root_rotate_policy_mismatch"
	CodeRootThreshold              = "root_rotate_threshold"
	CodeDelegationNotContained     = "delegation_not_contained"
)

// Error is a fail-closed confirmation failure with a stable code.
type Error struct {
	Code   string
	Detail string
}

// Error implements error.
func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

// fail builds a stable-coded error.
func fail(code, format string, args ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// CodeOf returns the stable failure code of err, or "" when err is not a
// schemeadmin failure.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

var (
	digestRe    = regexp.MustCompile(`^sha256:[A-Za-z0-9_-]{43}$`)
	schemeRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_.-]*-v[0-9]+$`)
	revisionRe  = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
	clcRe       = regexp.MustCompile(`^CLC-[0-9]+\.[0-9]+$`)
	principalRe = regexp.MustCompile(`^principal:[A-Za-z0-9_.:-]+$`)
	namespaceRe = regexp.MustCompile(`^/[A-Za-z0-9_.:/-]+$`)
)

// Digest returns `sha256:<base64url-unpadded>` over the exact bytes.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// CanonicalDigest returns the JCS (RFC 8785) digest of a JSON value.
func CanonicalDigest(v any) (string, error) {
	canonical, err := semantics.CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return Digest(canonical), nil
}

// decodeClosed decodes exactly one JSON value and refuses undeclared members.
// This is what makes an embedded `authorized: true` a shape error instead of a
// claim the deployer might be tempted to read.
// maxArtifactBytes bounds an untrusted package/transition/declaration before
// the closed decoder allocates it.
const maxArtifactBytes = 8 << 20

// maxDetachedSignatures and maxApprovalRecords bound loops over caller-supplied
// verification material.  They are far above any practical root/approval
// threshold and keep a hostile caller from turning signature verification into
// an unbounded CPU loop.
const (
	maxDetachedSignatures = 64
	maxApprovalRecords    = 4096
)

func decodeClosed(raw []byte, dst any) error {
	if len(raw) > maxArtifactBytes {
		return fmt.Errorf("artifact is %d bytes, limit is %d", len(raw), maxArtifactBytes)
	}
	if err := jsonstrict.Check(raw); err != nil {
		return fmt.Errorf("duplicate or invalid JSON member: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	// Require exactly one JSON value.  A syntax error here is also trailing
	// data: treating every non-nil error as EOF was the original bug that let
	// "garbage" and NUL bytes through.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing data after the object")
	}
	return nil
}

// FullCapabilityID prefixes a bare administration capability with the scheme.
func FullCapabilityID(capability string) string {
	return SchemeID + ":" + capability
}

// capabilityOf strips the scheme prefix from a full capability id.
func capabilityOf(fullID string) (string, bool) {
	prefix := SchemeID + ":"
	if !strings.HasPrefix(fullID, prefix) {
		return "", false
	}
	return strings.TrimPrefix(fullID, prefix), true
}

// maxIntValue is the largest value an int can hold.  Revision components are
// parsed into this range so `n*10 + digit` and `component+1` can never wrap.
var maxIntValue = int(^uint(0) >> 1)

// parseRevisionComponent parses one decimal revision component without
// overflowing int.
func parseRevisionComponent(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty revision component")
	}
	u, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("revision component %q is not a decimal integer", s)
	}
	if u > uint64(maxIntValue) {
		return 0, fmt.Errorf("revision component %q overflows int", s)
	}
	return int(u), nil
}

// MajorOf parses the integer major component of a `major.minor` revision.
func MajorOf(revision string) (int, error) {
	i := strings.IndexByte(revision, '.')
	if i <= 0 {
		return 0, fmt.Errorf("revision %q is not major.minor", revision)
	}
	n, err := parseRevisionComponent(revision[:i])
	if err != nil {
		return 0, fmt.Errorf("revision %q has an invalid major: %w", revision, err)
	}
	return n, nil
}

// MinorOf parses the integer minor component of a `major.minor` revision.
func MinorOf(revision string) (int, error) {
	i := strings.IndexByte(revision, '.')
	if i < 0 || i+1 >= len(revision) {
		return 0, fmt.Errorf("revision %q is not major.minor", revision)
	}
	n, err := parseRevisionComponent(revision[i+1:])
	if err != nil {
		return 0, fmt.Errorf("revision %q has an invalid minor: %w", revision, err)
	}
	return n, nil
}

// sha256Bytes returns the raw SHA-256 of b.
func sha256Bytes(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// keyIDOf returns the `sha256:` id over a certificate's SubjectPublicKeyInfo.
// Trust policies pin administration keys by this value.
func keyIDOf(rawSubjectPublicKeyInfo []byte) string {
	return Digest(rawSubjectPublicKeyInfo)
}

// allZero reports whether every byte is zero (the AIC placeholder key hash).
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// KeyID returns the `sha256:` key id of a certificate, the value a trust
// policy pins in `root_keys` / `next_root_keys`.
func KeyID(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return keyIDOf(cert.RawSubjectPublicKeyInfo)
}
