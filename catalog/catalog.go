// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Package catalog implements the signed capability catalog plane described in
// analysis/2026-10-22-authority-bounded-capability-publication-architecture.md
// §4.5–§4.7 and §5.
//
// Three immutable artifacts are defined:
//
//   - CLC-CAPABILITY-CATALOG-v1 — a generation-addressed snapshot of published
//     capabilities;
//   - CLC-CAPABILITY-CATALOG-DELTA-v1 — an add/replace/remove delta that only
//     applies to an exact base generation and digest;
//   - CLC-CATALOG-DISCOVERY-v1 — a candidate pointer that never carries an
//     execution verdict.
//
// The package validates artifacts and recomputes authority.  It does not fetch
// anything, does not trust transport, and does not read an `authorized`,
// `verified` or `status` boolean from an artifact: all three objects are closed,
// so such a member is a shape error.
//
// Signature verification is split exactly as in scheme administration: the
// caller verifies the detached PKCS#7 and hands in the recovered certificate;
// Verify re-checks the chain, the AIC principal and the key binding so the trust
// check cannot be skipped.
package catalog

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/varwof/register/internal/jsonstrict"
	"github.com/varwof/register/internal/schemedecl"
	"github.com/varwof/register/schemeadmin"
	"github.com/varwof/register/semantics"
)

// Artifact versions.
const (
	CatalogVersion   = "CLC-CAPABILITY-CATALOG-v1"
	DeltaVersion     = "CLC-CAPABILITY-CATALOG-DELTA-v1"
	DiscoveryVersion = "CLC-CATALOG-DISCOVERY-v1"
)

// maxArtifactBytes bounds an untrusted artifact before any parser allocates a
// full object graph.  Signatures are verified before a signed-verifier parses
// the artifact, so this cap is a backstop for the direct parse entry points.
const maxArtifactBytes = 8 << 20

// Stable failure codes.  A validation returns at most one of these.
const (
	CodeCatalogShape          = "catalog_shape"
	CodeCatalogDigest         = "catalog_digest_mismatch"
	CodeDuplicateEntry        = "catalog_duplicate_entry"
	CodeSchemeUnsupported     = "catalog_scheme_unsupported"
	CodeDeclarationMismatch   = "catalog_declaration_mismatch"
	CodeEntryOutsideAuthority = "catalog_entry_outside_authority"
	CodeIdentityMismatch      = "catalog_identity_mismatch"
	CodeBootstrap             = "catalog_bootstrap_required"
	CodeRollback              = "catalog_generation_rollback"
	CodeFork                  = "catalog_generation_fork"
	CodePreviousDigest        = "catalog_previous_digest_mismatch"
	CodeStateUnverified       = "state_unverified"
	CodeExpired               = "catalog_expired"
	CodeStale                 = "catalog_stale"
	CodeStatusUnavailable     = "catalog_status_unavailable"
	CodeStatusStale           = "catalog_status_stale"
	CodeProviderMismatch      = "catalog_provider_mismatch"

	CodeSignatureMissing    = "signature_missing"
	CodeSignatureInvalid    = "signature_invalid"
	CodeKeyRevoked          = "signature_key_revoked"
	CodeSignatureChain      = "signature_chain"
	CodeSignatureNoAIC      = "signature_no_aic"
	CodePublisherMismatch   = "publisher_mismatch"
	CodePublisherKeyBinding = "publisher_key_binding"

	CodeDeltaShape        = "delta_shape"
	CodeDeltaBase         = "delta_base_mismatch"
	CodeDeltaOperation    = "delta_operation_invalid"
	CodeDeltaDigest       = "delta_digest_mismatch"
	CodeDirectoryConflict = "directory_conflict"
	CodeShardMissing      = "directory_shard_missing"
	CodeDiscoveryShape    = "discovery_shape"
	CodeDiscoveryVerdict  = "discovery_verdict_member"
)

// Error is a fail-closed validation failure with a stable code.
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

func fail(code, format string, args ...any) *Error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// CodeOf returns the stable failure code of err, or "" when err is not a
// catalog failure.
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
	principalRe = regexp.MustCompile(`^principal:[A-Za-z0-9_.:-]+$`)
	nameRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*(/[a-z0-9][a-z0-9._-]*)*$`)
	referenceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
)

// Operation is one concrete published operation inside an entry.  The params
// use the ordinary CLC parameter representation, so a JSON array is an enum
// constraint rather than a list of independent values.
type Operation struct {
	Operation string         `json:"operation"`
	Params    map[string]any `json:"params,omitempty"`
}

// Status is an explicit status reference.  Its presence is meaningful; an absent
// status is never "healthy".
type Status struct {
	Reference string `json:"reference"`
	CheckedAt string `json:"checked_at"`
}

// Entry is one published capability.
type Entry struct {
	Capability        string      `json:"capability"`
	Provider          string      `json:"provider"`
	Scheme            string      `json:"scheme"`
	DeclarationDigest string      `json:"scheme_declaration_digest"`
	Operations        []Operation `json:"operations"`
	Status            *Status     `json:"status,omitempty"`
}

// Catalog is the immutable CLC-CAPABILITY-CATALOG-v1 artifact.  The struct is
// the closed schema: every member below is the whole of what a consumer reads.
type Catalog struct {
	Version        string  `json:"@version"`
	Domain         string  `json:"domain"`
	CatalogID      string  `json:"catalog_id"`
	Generation     int64   `json:"generation"`
	IssuedAt       string  `json:"issued_at"`
	ValidUntil     string  `json:"valid_until"`
	PreviousDigest string  `json:"previous_digest,omitempty"`
	Producer       string  `json:"producer"`
	Entries        []Entry `json:"entries"`
}

// ParseCatalog decodes exactly one closed catalog object and validates it.
func ParseCatalog(raw []byte) (*Catalog, error) {
	var c Catalog
	if err := decodeClosed(raw, &c); err != nil {
		return nil, fail(CodeCatalogShape, "%s", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks the artifact's own shape.  It does not check policy, freshness
// or authority; those need the deployer's inputs.
func (c *Catalog) Validate() error {
	if c.Version != CatalogVersion {
		return fail(CodeCatalogShape, "@version must be %q", CatalogVersion)
	}
	if !nameRe.MatchString(c.Domain) {
		return fail(CodeCatalogShape, "domain %q is not a catalog domain name", c.Domain)
	}
	if !nameRe.MatchString(c.CatalogID) {
		return fail(CodeCatalogShape, "catalog_id %q is not a catalog identity", c.CatalogID)
	}
	if c.Generation < 1 {
		return fail(CodeCatalogShape, "generation must be >= 1")
	}
	if !principalRe.MatchString(c.Producer) {
		return fail(CodeCatalogShape, "producer %q is not a principal", c.Producer)
	}
	issued, err := parseTime(c.IssuedAt)
	if err != nil {
		return fail(CodeCatalogShape, "issued_at: %s", err)
	}
	until, err := parseTime(c.ValidUntil)
	if err != nil {
		return fail(CodeCatalogShape, "valid_until: %s", err)
	}
	if !until.After(issued) {
		return fail(CodeCatalogShape, "valid_until must be after issued_at")
	}
	if c.Generation == 1 {
		if c.PreviousDigest != "" {
			return fail(CodeCatalogShape, "generation 1 must not carry previous_digest")
		}
	} else if !digestRe.MatchString(c.PreviousDigest) {
		return fail(CodeCatalogShape, "generation %d requires a previous_digest", c.Generation)
	}
	if len(c.Entries) == 0 {
		return fail(CodeCatalogShape, "catalog has no entries")
	}
	seen := make(map[string]bool, len(c.Entries))
	for i := range c.Entries {
		e := &c.Entries[i]
		if err := e.validate(); err != nil {
			return err
		}
		if seen[e.Capability] {
			return fail(CodeDuplicateEntry, "capability %q appears more than once", e.Capability)
		}
		seen[e.Capability] = true
	}
	return nil
}

func (e *Entry) validate() error {
	if !schemeRe.MatchString(e.Scheme) {
		return fail(CodeCatalogShape, "entry scheme %q is not a scheme id", e.Scheme)
	}
	if !strings.HasPrefix(e.Capability, e.Scheme+":") || len(e.Capability) == len(e.Scheme)+1 {
		return fail(CodeCatalogShape, "capability %q is not inside scheme %q", e.Capability, e.Scheme)
	}
	if err := semantics.ValidateCapabilityID(e.Capability); err != nil {
		return fail(CodeCatalogShape, "capability %q: %s", e.Capability, err)
	}
	if strings.TrimSpace(e.Provider) == "" || strings.ContainsAny(e.Provider, " \t\r\n") {
		return fail(CodeCatalogShape, "provider %q is not an identity reference", e.Provider)
	}
	if !digestRe.MatchString(e.DeclarationDigest) {
		return fail(CodeCatalogShape, "entry %q has no valid scheme_declaration_digest", e.Capability)
	}
	if len(e.Operations) == 0 {
		return fail(CodeCatalogShape, "entry %q has no operations", e.Capability)
	}
	ops := make(map[string]bool, len(e.Operations))
	for _, op := range e.Operations {
		if strings.TrimSpace(op.Operation) == "" {
			return fail(CodeCatalogShape, "entry %q has an unnamed operation", e.Capability)
		}
		if err := semantics.ValidateOperationParams(op.Params); err != nil {
			return fail(CodeCatalogShape, "entry %q operation %q params: %s", e.Capability, op.Operation, err)
		}
		if ops[op.Operation] {
			return fail(CodeCatalogShape, "entry %q repeats operation %q", e.Capability, op.Operation)
		}
		ops[op.Operation] = true
	}
	if e.Status != nil {
		if !referenceRe.MatchString(e.Status.Reference) {
			return fail(CodeCatalogShape, "entry %q has no usable status reference", e.Capability)
		}
		if _, err := parseTime(e.Status.CheckedAt); err != nil {
			return fail(CodeCatalogShape, "entry %q status.checked_at: %s", e.Capability, err)
		}
	}
	return nil
}

// Digest returns the content address of the canonical catalog object.
func (c Catalog) Digest() (string, error) {
	return schemeadmin.CanonicalDigest(c)
}

// OperationGrant projects one published operation back into the CLC grant form
// used for the authority comparison.
func (op Operation) Grant(capability string) semantics.Grant {
	return semantics.Grant{ID: capability, Params: op.Params}
}

// decodeClosed decodes exactly one JSON value and refuses undeclared members.
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
	// dec.More() is false for trailing ']'/'}', so it is not a closed-object
	// check.  Require the next decode to report io.EOF exactly.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing data after the object")
	}
	return nil
}

func parseTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, fmt.Errorf("missing")
	}
	return time.Parse(time.RFC3339, raw)
}

// KeyID returns the sha256: id of a certificate's SubjectPublicKeyInfo.
func KeyID(cert *x509.Certificate) string {
	return schemeadmin.KeyID(cert)
}

// Digest returns the sha256: content address of raw bytes.
func Digest(raw []byte) string {
	return schemeadmin.Digest(raw)
}

func seconds(n int64) time.Duration {
	return time.Duration(n) * time.Second
}

// DigestOfDeclaration returns the content address of a CLC-SCHEME-v1
// declaration: sha256 over its JCS form without the `digest` member.  Policies
// and catalog entries pin the same value, so no second digest convention exists.
func DigestOfDeclaration(raw []byte) string {
	digest, err := schemedecl.DigestOf(raw)
	if err != nil {
		return ""
	}
	return digest
}
