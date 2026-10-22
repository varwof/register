// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import (
	"time"

	"github.com/varwof/register/internal/schemedecl"
)

// Package is the immutable CLC-SCHEME-PACKAGE-v1 artifact.  The struct is the
// closed schema: every member below is the whole of what a deployer reads.
//
// The payload bytes are not carried here.  `ValidatePayload` binds this object
// to the exact definition and declaration bytes the deployment fixture pins, so
// the digest members can never be satisfied by a re-encoded object.
type Package struct {
	Version               string `json:"@version"`
	Scheme                string `json:"scheme"`
	Revision              string `json:"revision"`
	DefinitionDigest      string `json:"definition_digest"`
	DeclarationDigest     string `json:"declaration_digest"`
	CLCRevision           string `json:"clc_revision"`
	ChangeClass           string `json:"change_class"`
	PreviousPackageDigest string `json:"previous_package_digest,omitempty"`
	Publisher             string `json:"publisher"`
	Generation            int64  `json:"generation"`
	IssuedAt              string `json:"issued_at,omitempty"`
	ValidUntil            string `json:"valid_until,omitempty"`
}

// ParsePackage decodes a package from its exact JSON bytes.  Undeclared members
// are refused, so an embedded `authorized`/`verified`/`approved` member is a
// shape error.
func ParsePackage(raw []byte) (Package, error) {
	var pkg Package
	if err := decodeClosed(raw, &pkg); err != nil {
		return Package{}, fail(CodePackageShape, "%s", err)
	}
	if err := ValidatePackage(pkg); err != nil {
		return Package{}, err
	}
	return pkg, nil
}

// ValidatePackage checks the closed package schema and its internal
// consistency.  It does not look at payload bytes; use ValidatePayload for
// that.
func ValidatePackage(pkg Package) error {
	if pkg.Version != PackageVersion {
		return fail(CodePackageShape, "@version must be %q, got %q", PackageVersion, pkg.Version)
	}
	if !schemeRe.MatchString(pkg.Scheme) {
		return fail(CodePackageShape, "scheme %q does not match vendor/product-vN", pkg.Scheme)
	}
	if !revisionRe.MatchString(pkg.Revision) {
		return fail(CodePackageShape, "revision %q is not major.minor", pkg.Revision)
	}
	if !digestRe.MatchString(pkg.DefinitionDigest) {
		return fail(CodePackageShape, "definition_digest %q is not a sha256 digest", pkg.DefinitionDigest)
	}
	if !digestRe.MatchString(pkg.DeclarationDigest) {
		return fail(CodePackageShape, "declaration_digest %q is not a sha256 digest", pkg.DeclarationDigest)
	}
	if !clcRe.MatchString(pkg.CLCRevision) {
		return fail(CodePackageShape, "clc_revision %q is not CLC-N.N", pkg.CLCRevision)
	}
	switch pkg.ChangeClass {
	case ChangePatch, ChangeMinor, ChangeMajor:
	default:
		return fail(CodePackageShape, "change_class %q is not patch|minor|major", pkg.ChangeClass)
	}
	if !principalRe.MatchString(pkg.Publisher) {
		return fail(CodePackageShape, "publisher %q is not principal:<id>", pkg.Publisher)
	}
	if pkg.Generation < 1 {
		return fail(CodePackageShape, "generation must be >= 1, got %d", pkg.Generation)
	}
	if pkg.PreviousPackageDigest != "" && !digestRe.MatchString(pkg.PreviousPackageDigest) {
		return fail(CodePackageShape, "previous_package_digest %q is not a sha256 digest", pkg.PreviousPackageDigest)
	}
	if pkg.Generation == 1 && pkg.PreviousPackageDigest != "" {
		return fail(CodePackageShape, "the first package must not declare previous_package_digest")
	}
	if pkg.Generation > 1 && pkg.PreviousPackageDigest == "" {
		return fail(CodePackageShape, "generation %d requires previous_package_digest", pkg.Generation)
	}
	if pkg.IssuedAt != "" {
		if _, err := time.Parse(time.RFC3339, pkg.IssuedAt); err != nil {
			return fail(CodePackageShape, "issued_at %q is not RFC3339", pkg.IssuedAt)
		}
	}
	if pkg.ValidUntil != "" {
		if _, err := time.Parse(time.RFC3339, pkg.ValidUntil); err != nil {
			return fail(CodePackageShape, "valid_until %q is not RFC3339", pkg.ValidUntil)
		}
	}
	return nil
}

// PackageDigest is the content address of a package object.
func PackageDigest(pkg Package) (string, error) {
	return CanonicalDigest(pkg)
}

// ValidatePayload binds a package to the exact definition and declaration
// bytes.  The declaration is additionally self-checked (version, digest,
// scheme, CLC revision).  It does not parse the definition's capability list:
// the deployer's authority check uses the declaration, so a declaration that
// names an undeclared definition capability is a known limitation, not a check
// this function performs.
func ValidatePayload(pkg Package, definition, declaration []byte) error {
	if len(definition) == 0 {
		return fail(CodePackageDigestMismatch, "definition payload is empty")
	}
	if len(declaration) == 0 {
		return fail(CodePackageDigestMismatch, "declaration payload is empty")
	}
	if got := Digest(definition); got != pkg.DefinitionDigest {
		return fail(CodePackageDigestMismatch, "definition: want %s, got %s", pkg.DefinitionDigest, got)
	}
	if got := Digest(declaration); got != pkg.DeclarationDigest {
		return fail(CodePackageDigestMismatch, "declaration: want %s, got %s", pkg.DeclarationDigest, got)
	}

	decl, err := ParseDeclaration(declaration)
	if err != nil {
		return err
	}
	if decl.Scheme != pkg.Scheme {
		return fail(CodeDeclarationInvalid, "declaration names scheme %q, package names %q", decl.Scheme, pkg.Scheme)
	}
	if decl.CLCRevision != pkg.CLCRevision {
		return fail(CodeDeclarationInvalid, "declaration requires %q, package requires %q", decl.CLCRevision, pkg.CLCRevision)
	}
	return nil
}

// ParseDeclaration validates a CLC-SCHEME-v1 declaration from its exact bytes.
func ParseDeclaration(raw []byte) (*schemedecl.Declaration, error) {
	var decl schemedecl.Declaration
	if err := decodeClosed(raw, &decl); err != nil {
		return nil, fail(CodeDeclarationInvalid, "%s", err)
	}
	if err := decl.Validate(); err != nil {
		return nil, fail(CodeDeclarationInvalid, "%s", err)
	}
	if decl.Version != DeclarationVersion {
		return nil, fail(CodeDeclarationInvalid, "@version must be %q", DeclarationVersion)
	}
	return &decl, nil
}
