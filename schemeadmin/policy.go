// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/varwof/register/semantics"
)

// TrustPolicy is the deployer's local bootstrap configuration.  It is not
// published authority: every value here is a local adoption decision that may be
// stricter than global publication.
//
// RootKeys are `sha256:` ids over a certificate's SubjectPublicKeyInfo.
// RootGrants are the configured authority the publisher's grant must stay
// inside; they are pinned together with the root administration package digest
// so that the bootstrap is auditable.
type TrustPolicy struct {
	RootPackageDigest string            `json:"root_package_digest"`
	RootKeys          []string          `json:"root_keys"`
	RootThreshold     int               `json:"root_threshold"`
	RootGrants        []semantics.Grant `json:"root_grants"`

	SupportedCLCRevisions []string `json:"supported_clc_revisions"`
	NamespacePrefixes     []string `json:"namespace_prefixes"`
	MaxMajor              int      `json:"max_major"`

	// AdministrationDeclaration is the pinned CLC-SCHEME-v1 declaration of the
	// administration scheme itself.  It is what gives `namespace` its
	// path-prefix domain and `change_class`/`clc_revision` their enum domains;
	// without it CLC would fall back to shape inference and path containment
	// would become exact equality.
	AdministrationDeclaration json.RawMessage `json:"administration_declaration"`

	// ObservedAt is the deployer's clock input, never "now()" read inside the
	// library.  Freshness decisions must be replayable.
	ObservedAt          string `json:"observed_at"`
	MaxStalenessSeconds int64  `json:"max_staleness_seconds,omitempty"`
	ApprovalThreshold   int    `json:"approval_threshold,omitempty"`

	// Separately configured next root.  A rotation is accepted only when the
	// current root authorizes it and this next-root threshold is met.
	NextRootPackageDigest string   `json:"next_root_package_digest,omitempty"`
	NextRootKeys          []string `json:"next_root_keys,omitempty"`
	NextRootThreshold     int      `json:"next_root_threshold,omitempty"`
}

// RegistryEntry is one accepted generation.
type RegistryEntry struct {
	Generation    int64  `json:"generation"`
	PackageDigest string `json:"package_digest"`
}

// Revocation is the local record of a signed tombstone.  Revoked digests stay
// revoked; nothing is deleted.
type Revocation struct {
	PackageDigest     string `json:"package_digest"`
	Generation        int64  `json:"generation"`
	EffectiveTime     string `json:"effective_time"`
	Reason            string `json:"reason"`
	ReplacementDigest string `json:"replacement_digest,omitempty"`

	// Tombstone is the exact signed revocation transition and Signature is the
	// detached PKCS#7 over it.  A state file cannot invent a revocation without
	// a trusted signature.
	Tombstone []byte `json:"tombstone,omitempty"`
	Signature []byte `json:"signature,omitempty"`
}

// Approval is one recorded exact approval for a package/transition pair.  The
// signature is a detached PKCS#7 over ApprovalSigningBytes (the canonical
// scheme:approve operation); Approver names the AIC principal that must match
// the recovered signer certificate.
type Approval struct {
	PackageDigest    string `json:"package_digest"`
	TransitionDigest string `json:"transition_digest"`
	Approver         string `json:"approver"`
	Signature        []byte `json:"signature,omitempty"`
}

// RegistryState is the deployer's local view of one scheme namespace.
type RegistryState struct {
	Scheme        string          `json:"scheme"`
	Revision      string          `json:"revision,omitempty"`
	Generation    int64           `json:"generation"`
	PackageDigest string          `json:"package_digest"`
	History       []RegistryEntry `json:"history,omitempty"`
	Revoked       []Revocation    `json:"revoked,omitempty"`
	Approvals     []Approval      `json:"approvals,omitempty"`
}

// HeadOf returns the highest generation recorded in the state.
func (s RegistryState) HeadOf() int64 {
	head := s.Generation
	for _, e := range s.History {
		if e.Generation > head {
			head = e.Generation
		}
	}
	return head
}

// digestAt returns the digest recorded for one generation, if any.
func (s RegistryState) digestAt(generation int64) (string, bool) {
	if s.Generation == generation && s.PackageDigest != "" {
		return s.PackageDigest, true
	}
	for _, e := range s.History {
		if e.Generation == generation {
			return e.PackageDigest, true
		}
	}
	return "", false
}

// isRevoked reports whether a digest appears in the tombstone set.
func (s RegistryState) isRevoked(digest string) bool {
	for _, r := range s.Revoked {
		if r.PackageDigest == digest {
			return true
		}
	}
	return false
}

// isRevokedAt applies the tombstone's effective time.  A future-effective
// revocation does not revoke early; an invalid timestamp or a replacement that
// points at the revoked digest is a state error rather than a silent bypass.
func (s RegistryState) isRevokedAt(digest string, now time.Time) (bool, error) {
	for _, r := range s.Revoked {
		if r.PackageDigest != digest {
			continue
		}
		if r.ReplacementDigest != "" && r.ReplacementDigest == r.PackageDigest {
			return false, fmt.Errorf("revocation %s names itself as its replacement", digest)
		}
		if r.EffectiveTime == "" {
			return true, nil
		}
		t, err := time.Parse(time.RFC3339, r.EffectiveTime)
		if err != nil {
			return false, fmt.Errorf("revocation %s effective_time %q is not RFC3339", digest, r.EffectiveTime)
		}
		if !now.Before(t) {
			return true, nil
		}
	}
	return false, nil
}

// countApprovals counts exact approvals for the pair.
func (s RegistryState) countApprovals(pkgDigest, trDigest string) int {
	n := 0
	for _, a := range s.Approvals {
		if a.PackageDigest == pkgDigest && a.TransitionDigest == trDigest {
			n++
		}
	}
	return n
}

// Confirmation is the complete input of one deployer decision.  Every value is
// explicit: the library never reads a clock, a network or an environment.
type Confirmation struct {
	Package    Package
	Transition Transition

	// Definition and Declaration are the exact payload bytes the package
	// digests pin.
	Definition  []byte
	Declaration []byte

	// TransitionBytes/TransitionSignature are the exact signed transition
	// artifact.  ConfirmSigned supplies them so a revoke can persist a tombstone
	// signature in state.
	TransitionBytes     []byte
	TransitionSignature []byte

	// PublisherCert is the certificate recovered from the detached PKCS#7
	// signature over the package bytes.  Roots are the trust anchors the
	// certificate chain must reach.
	PublisherCert *x509.Certificate
	Roots         []*x509.Certificate

	// rootSigners is set only by ConfirmSigned, after every detached signature
	// has been verified and every signer certificate has chained to Roots.  It
	// is unexported so a caller of Confirm cannot claim a threshold that was
	// never verified.
	rootSigners []*x509.Certificate

	State  RegistryState
	Policy TrustPolicy
}

// ConfirmationResult is the replayable decision record.  It binds every input
// digest and never carries a bare trust boolean: the verdict is the deployer's
// own recomputation.
type ConfirmationResult struct {
	Verdict    string `json:"verdict"`
	Reason     string `json:"reason,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Action     string `json:"action"`
	Scheme     string `json:"scheme"`
	Namespace  string `json:"namespace"`
	Generation int64  `json:"generation"`

	PackageDigest              string `json:"package_digest"`
	TransitionDigest           string `json:"transition_digest"`
	ManagementOperationDigest  string `json:"management_operation_digest,omitempty"`
	ApprovalOperationDigest    string `json:"approval_operation_digest,omitempty"`
	PublisherCertificateDigest string `json:"publisher_certificate_digest,omitempty"`
	PublisherKeyID             string `json:"publisher_key_id,omitempty"`
	TrustPolicyDigest          string `json:"trust_policy_digest,omitempty"`
	RegistryStateDigest        string `json:"registry_state_digest,omitempty"`
	InputsDigest               string `json:"inputs_digest,omitempty"`

	// signed is set only by ConfirmSigned after all detached signatures and
	// transition signatures verified.  State writers require it so a caller
	// cannot fabricate an accept result and persist it.
	signed bool

	RevokedPackageDigest    string `json:"revoked_package_digest,omitempty"`
	RevocationReason        string `json:"revocation_reason,omitempty"`
	RevocationEffectiveTime string `json:"revocation_effective_time,omitempty"`
	ReplacementDigest       string `json:"replacement_digest,omitempty"`
	TombstoneGeneration     int64  `json:"tombstone_generation,omitempty"`
}

// policyTime parses the deployer clock input.
func policyTime(p TrustPolicy) (time.Time, error) {
	if p.ObservedAt == "" {
		return time.Time{}, fail(CodePackageStale, "policy.observed_at is required for freshness decisions")
	}
	t, err := time.Parse(time.RFC3339, p.ObservedAt)
	if err != nil {
		return time.Time{}, fail(CodePackageStale, "policy.observed_at %q is not RFC3339", p.ObservedAt)
	}
	return t, nil
}

// ValidatePolicy checks the bootstrap configuration is usable at all.
func ValidatePolicy(p TrustPolicy) error {
	if p.RootPackageDigest != "" && !digestRe.MatchString(p.RootPackageDigest) {
		return fail(CodePackageShape, "policy.root_package_digest is not a sha256 digest")
	}
	if len(p.RootKeys) != 0 && p.RootThreshold < 1 {
		return fail(CodePackageShape, "policy.root_threshold must be >= 1 when root keys are configured")
	}
	if p.RootThreshold < 0 {
		return fail(CodePackageShape, "policy.root_threshold must be >= 0")
	}
	if p.RootThreshold > len(p.RootKeys) {
		return fail(CodePackageShape, "policy.root_threshold %d exceeds the %d configured root keys", p.RootThreshold, len(p.RootKeys))
	}
	if p.ApprovalThreshold < 0 {
		return fail(CodePackageShape, "policy.approval_threshold must be >= 0")
	}
	if p.MaxStalenessSeconds < 0 {
		return fail(CodePackageShape, "policy.max_staleness_seconds must be >= 0")
	}
	if p.MaxMajor < 1 {
		return fail(CodePackageShape, "policy.max_major must be >= 1")
	}
	if len(p.RootKeys) != 0 {
		if err := validateDistinctDigests("root_keys", p.RootKeys); err != nil {
			return err
		}
	}
	if len(p.NextRootKeys) != 0 {
		if err := validateDistinctDigests("next_root_keys", p.NextRootKeys); err != nil {
			return err
		}
	}
	if p.NextRootThreshold < 0 {
		return fail(CodePackageShape, "policy.next_root_threshold must be >= 0")
	}
	if p.NextRootThreshold > len(p.NextRootKeys) {
		return fail(CodePackageShape, "policy.next_root_threshold %d exceeds the %d configured next root keys", p.NextRootThreshold, len(p.NextRootKeys))
	}
	if p.NextRootPackageDigest != "" && !digestRe.MatchString(p.NextRootPackageDigest) {
		return fail(CodePackageShape, "policy.next_root_package_digest is not a sha256 digest")
	}
	for _, prefix := range p.NamespacePrefixes {
		if prefix == "" || prefix == "/" || !strings.HasPrefix(prefix, "/") || path.Clean(prefix) != prefix {
			return fail(CodePackageShape, "policy.namespace_prefixes entry %q must be a clean non-root absolute prefix", prefix)
		}
	}
	if len(p.AdministrationDeclaration) == 0 {
		return fail(CodeDeclarationInvalid, "policy.administration_declaration is required")
	}
	decl, err := ParseDeclaration(p.AdministrationDeclaration)
	if err != nil {
		return err
	}
	if decl.Scheme != SchemeID {
		return fail(CodeDeclarationInvalid, "policy administration declaration names %q, want %q", decl.Scheme, SchemeID)
	}
	for _, k := range p.NextRootKeys {
		if !digestRe.MatchString(k) {
			return fail(CodePackageShape, "policy.next_root_keys entry %q is not a sha256 digest", k)
		}
	}
	return nil
}

func validateDistinctDigests(field string, keys []string) error {
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if !digestRe.MatchString(k) {
			return fail(CodePackageShape, "policy.%s entry %q is not a sha256 digest", field, k)
		}
		if seen[k] {
			return fail(CodePackageShape, "policy.%s contains duplicate key %q", field, k)
		}
		seen[k] = true
	}
	return nil
}
