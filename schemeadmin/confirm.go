// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	pki "github.com/varwof/types"

	"github.com/varwof/register/semantics"
)

// Confirm runs the deployer confirmation algorithm.  It returns a
// ConfirmationResult for every call; a non-nil error means the package was
// refused and the result's Verdict is complete.
//
// The publisher certificate is the one recovered from the detached PKCS#7
// signature over the exact package bytes.  Confirm re-checks that it chains to
// `Roots` and that its AIC principal and key hash bind the package's
// `publisher`, so a caller that skipped the chain check still cannot smuggle a
// signer past the deployer.
func confirm(c Confirmation) (ConfirmationResult, error) {
	res := ConfirmationResult{
		Verdict:    VerdictReject,
		Action:     c.Transition.Action,
		Scheme:     c.Package.Scheme,
		Namespace:  c.Transition.Namespace,
		Generation: c.Package.Generation,
	}
	if c.Transition.Action == ActionRevoke {
		res.RevokedPackageDigest = c.Transition.FromDigest
		res.RevocationReason = c.Transition.RevocationReason
		res.RevocationEffectiveTime = c.Transition.RevocationEffectiveTime
		res.ReplacementDigest = c.Transition.ReplacementDigest
		if c.Transition.TombstoneGeneration != nil {
			res.TombstoneGeneration = *c.Transition.TombstoneGeneration
		}
	}

	now, err := policyTime(c.Policy)
	if err != nil {
		return res, err
	}

	if d, err := PackageDigest(c.Package); err == nil {
		res.PackageDigest = d
	}
	if d, err := TransitionDigest(c.Transition); err == nil {
		res.TransitionDigest = d
	}
	if c.PublisherCert != nil {
		res.PublisherCertificateDigest = Digest(c.PublisherCert.Raw)
		res.PublisherKeyID = keyIDOf(c.PublisherCert.RawSubjectPublicKeyInfo)
	}
	if d, err := CanonicalDigest(c.Policy); err == nil {
		res.TrustPolicyDigest = d
	}
	if d, err := CanonicalDigest(c.State); err == nil {
		res.RegistryStateDigest = d
	}
	if op, err := BuildManagementOperation(c.Package, c.Transition); err == nil {
		digest, derr := OperationDigest(op)
		if derr != nil {
			return res, fail(CodePackageShape, "management operation digest: %s", derr)
		}
		res.ManagementOperationDigest = digest
	}
	if op, err := BuildApprovalOperation(c.Package, c.Transition); err == nil {
		digest, derr := OperationDigest(op)
		if derr != nil {
			return res, fail(CodePackageShape, "approval operation digest: %s", derr)
		}
		res.ApprovalOperationDigest = digest
	}

	err = decide(c, &res, now)
	if err != nil {
		res.Reason = CodeOf(err)
		if res.Reason == "" {
			res.Reason = "internal"
		}
		res.Detail = err.Error()
		res.InputsDigest = inputsDigest(&res)
		return res, err
	}
	res.Verdict = VerdictAccept
	res.InputsDigest = inputsDigest(&res)
	return res, nil
}

func decide(c Confirmation, res *ConfirmationResult, now time.Time) error {
	if err := ValidatePolicy(c.Policy); err != nil {
		return err
	}
	if err := ValidatePackage(c.Package); err != nil {
		return err
	}
	if err := ValidateTransition(c.Transition); err != nil {
		return err
	}
	if err := ValidatePayload(c.Package, c.Definition, c.Declaration); err != nil {
		return err
	}

	// Package and transition must describe the same package.
	if c.Package.Scheme != c.Transition.Scheme {
		return fail(CodePackageTransitionMismatch, "package scheme %q, transition scheme %q", c.Package.Scheme, c.Transition.Scheme)
	}
	if c.Package.Generation != c.Transition.ToGeneration {
		return fail(CodePackageTransitionMismatch, "package generation %d, transition to_generation %d", c.Package.Generation, c.Transition.ToGeneration)
	}
	if c.Package.ChangeClass != c.Transition.ChangeClass {
		return fail(CodePackageTransitionMismatch, "package change_class %q, transition change_class %q", c.Package.ChangeClass, c.Transition.ChangeClass)
	}
	if c.Package.CLCRevision != c.Transition.TargetCLCRevision {
		return fail(CodePackageTransitionMismatch, "package clc_revision %q, transition target_clc_revision %q", c.Package.CLCRevision, c.Transition.TargetCLCRevision)
	}
	if d, err := PackageDigest(c.Package); err != nil || d != c.Transition.ToDigest {
		return fail(CodePackageTransitionMismatch, "package digest %s, transition to_digest %s", res.PackageDigest, c.Transition.ToDigest)
	}
	if c.Transition.FromDigest != "" && c.Package.PreviousPackageDigest != c.Transition.FromDigest {
		return fail(CodePackageTransitionMismatch, "previous_package_digest %q, transition from_digest %q", c.Package.PreviousPackageDigest, c.Transition.FromDigest)
	}

	// Publisher signature, chain and AIC binding.
	aic, err := verifyPublisher(c.Package, c.PublisherCert, c.Roots, now)
	if err != nil {
		return err
	}

	// The deployer's supported language revisions.
	if !containsString(c.Policy.SupportedCLCRevisions, c.Package.CLCRevision) {
		return fail(CodeCLCSupported, "package requires %q, policy supports %v", c.Package.CLCRevision, c.Policy.SupportedCLCRevisions)
	}
	if !containsString(c.Policy.SupportedCLCRevisions, c.Transition.TargetCLCRevision) {
		return fail(CodeCLCSupported, "transition requires %q, policy supports %v", c.Transition.TargetCLCRevision, c.Policy.SupportedCLCRevisions)
	}

	// Root rotation has a key-level pre-check that no grant can override.
	if c.Transition.Action == ActionRootRotate {
		if err := checkRootRotation(c); err != nil {
			return err
		}
	}

	// Authority: extract the grant, prove it is inside the configured root
	// authority, then let CLC decide.
	op, err := BuildManagementOperation(c.Package, c.Transition)
	if err != nil {
		return err
	}
	capability, _ := capabilityOf(op.ID)
	dm := domainMapFor(c.Policy.AdministrationDeclaration, capability)

	grants := grantsFor(aic, op.ID)
	if len(grants) == 0 {
		return fail(CodeAuthorityNoGrant, "AIC declares no %s capability", op.ID)
	}
	contained, detail := containGrants(grants, c.Policy.RootGrants, dm)
	if len(contained) == 0 {
		return fail(CodeAuthorityNotContained, "%s", detail)
	}
	decision := semantics.AuthorizeSetWithDomains(contained, op, dm)
	if decision.Verdict != semantics.VerdictAllow {
		if decision.Reason != "" {
			return fail(CodeAuthorityNotAuthorized, "CLC %s: %s", decision.Verdict, decision.Reason)
		}
		return fail(CodeAuthorityNotAuthorized, "CLC %s", decision.Verdict)
	}

	// Local adoption policy.
	if !namespaceUnder(c.Transition.Namespace, c.Policy.NamespacePrefixes) {
		return fail(CodeNamespaceOutsidePolicy, "namespace %q is outside %v", c.Transition.Namespace, c.Policy.NamespacePrefixes)
	}
	major, err := MajorOf(c.Package.Revision)
	if err != nil {
		return fail(CodePackageShape, "%s", err)
	}
	if major > c.Policy.MaxMajor {
		return fail(CodeMajorExceedsLimit, "revision %s major %d exceeds policy max_major %d", c.Package.Revision, major, c.Policy.MaxMajor)
	}

	// Generation continuity and the registry comparison.
	if err := checkState(c, res); err != nil {
		return err
	}

	// Revocation and tombstones.  A revoked digest stays revoked once its
	// effective time has arrived; a future tombstone is not applied early.  The
	// persisted tombstones themselves must be signed by a trusted signer.
	if err := c.State.verifyRevocations(c.Roots, now); err != nil {
		return err
	}
	if revoked, err := c.State.isRevokedAt(c.Transition.FromDigest, now); err != nil {
		return fail(CodeRevocationInvalid, "%s", err)
	} else if revoked {
		return fail(CodePackageRevoked, "from_digest %s is revoked", c.Transition.FromDigest)
	}
	if revoked, err := c.State.isRevokedAt(res.PackageDigest, now); err != nil {
		return fail(CodeRevocationInvalid, "%s", err)
	} else if revoked {
		return fail(CodePackageRevoked, "package digest %s is revoked", res.PackageDigest)
	}

	// Freshness, from the deployer's own clock input.
	if err := checkFreshness(c.Package, c.Policy); err != nil {
		return err
	}

	// Approvals, when the local policy requires them.  Only signed approvals
	// that bind this exact package/transition and a distinct scheme:approve
	// principal count.
	if c.Policy.ApprovalThreshold > 0 {
		n, err := verifyApprovals(c, now, res.PackageDigest, res.TransitionDigest)
		if err != nil {
			return err
		}
		if n < c.Policy.ApprovalThreshold {
			return fail(CodeApprovalInsufficient, "have %d distinct verified approvals, policy requires %d", n, c.Policy.ApprovalThreshold)
		}
	}

	return nil
}

// Confirm is retained only as a fail-closed compatibility stub.  A caller that
// has a recovered certificate but no detached signature proof must not be able
// to admit a package; use ConfirmSigned, which verifies the exact package and
// transition bytes.
func Confirm(c Confirmation) (ConfirmationResult, error) {
	res := ConfirmationResult{
		Verdict:    VerdictReject,
		Action:     c.Transition.Action,
		Scheme:     c.Package.Scheme,
		Namespace:  c.Transition.Namespace,
		Generation: c.Package.Generation,
	}
	return res, fail(CodeSignatureMissing, "Confirm does not verify signatures; use ConfirmSigned")
}

// verifyCertificate checks a certificate chain and the AIC key binding.  It is
// the common trust check for a publisher and for an approval signer.
func verifyCertificate(cert *x509.Certificate, roots []*x509.Certificate, now time.Time) (*pki.AIC, error) {
	if cert == nil {
		return nil, fail(CodeSignatureMissing, "signer certificate is required")
	}
	if len(roots) == 0 {
		return nil, fail(CodeSignatureChain, "no trust roots configured")
	}
	pool := x509.NewCertPool()
	for _, r := range roots {
		if r != nil {
			pool.AddCert(r)
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: now,
	}); err != nil {
		return nil, fail(CodeSignatureChain, "%s", err)
	}

	aic, err := pki.ParseAIC(cert)
	if err != nil {
		return nil, fail(CodeSignatureNoAIC, "%s", err)
	}
	if aic == nil {
		return nil, fail(CodeSignatureNoAIC, "certificate carries no AIC extension")
	}
	if err := pki.ValidateAIC(aic); err != nil {
		return nil, fail(CodeSignatureNoAIC, "AIC is invalid: %s", err)
	}
	if len(aic.PrincipalUid.KeyHash) == 0 || allZero(aic.PrincipalUid.KeyHash) {
		return nil, fail(CodePublisherKeyBinding, "AIC carries no principal key hash")
	}
	if !bytes.Equal(aic.PrincipalUid.KeyHash, mustKeyHash(cert)) {
		return nil, fail(CodePublisherKeyBinding, "AIC key hash does not match the certificate key")
	}
	return aic, nil
}

// verifyPublisher checks the certificate chain, the AIC presence, the principal
// binding and the certificate/key binding.
func verifyPublisher(pkg Package, cert *x509.Certificate, roots []*x509.Certificate, now time.Time) (*pki.AIC, error) {
	aic, err := verifyCertificate(cert, roots, now)
	if err != nil {
		return nil, err
	}
	want := strings.TrimPrefix(pkg.Publisher, "principal:")
	id := aic.PrincipalUid.Identifier
	realm := aic.PrincipalUid.Realm
	if want != id && want != realm+":"+id {
		return nil, fail(CodePublisherMismatch, "package names %q, AIC names %q", pkg.Publisher, realm+":"+id)
	}
	return aic, nil
}

// mustKeyHash returns the SHA-256 of the certificate's SubjectPublicKeyInfo.
func mustKeyHash(cert *x509.Certificate) []byte {
	return sha256Bytes(cert.RawSubjectPublicKeyInfo)
}

// grantsFor converts the AIC capabilities that cover the operation capability
// into CLC grants.  A wildcard grant (`scheme:*`) is kept as a wildcard so the
// CLC relation decides coverage; an optional `params`/`param_bounds` envelope
// is preserved as bounds instead of being mistaken for concrete params.  A
// capability with no parameters becomes an unconstrained grant, which the root
// containment check refuses when the root authority declares parameters.
func grantsFor(aic *pki.AIC, fullID string) []semantics.Grant {
	if aic == nil {
		return nil
	}
	out := make([]semantics.Grant, 0, len(aic.Capabilities))
	for _, cap := range aic.Capabilities {
		if !coversGrantID(cap.FullID(), fullID) {
			continue
		}
		g, ok := grantFromAICCapability(cap)
		if !ok {
			continue
		}
		out = append(out, g)
	}
	return out
}

// coversGrantID reports whether a granted capability id covers a concrete id,
// including the CLC trailing-segment wildcard.
func coversGrantID(grantID, opID string) bool {
	if grantID == opID {
		return true
	}
	if strings.HasSuffix(grantID, ":*") {
		prefix := strings.TrimSuffix(grantID, "*")
		return len(opID) > len(prefix) && strings.HasPrefix(opID, prefix)
	}
	return false
}

// grantFromAICCapability decodes the AIC capability parameter container.  The
// envelope form uses top-level `params` and/or `param_bounds`; a bare object is
// treated as concrete params (the historical shape).
func grantFromAICCapability(cap pki.Capability) (semantics.Grant, bool) {
	g := semantics.Grant{ID: cap.FullID()}
	if len(cap.Parameters) == 0 {
		return g, true
	}
	var raw map[string]any
	if err := json.Unmarshal(cap.Parameters, &raw); err != nil {
		return semantics.Grant{}, false
	}
	params, hasParams := raw["params"].(map[string]any)
	bounds, hasBounds := raw["param_bounds"].(map[string]any)
	if _, present := raw["params"]; present && !hasParams {
		return semantics.Grant{}, false
	}
	if _, present := raw["param_bounds"]; present && !hasBounds {
		return semantics.Grant{}, false
	}
	if hasParams || hasBounds {
		g.Params = params
		g.ParamBounds = bounds
		return g, true
	}
	g.Params = raw
	return g, true
}

// containGrants keeps the grants that sit inside at least one root authority
// grant, using the CLC-1.19 declared-domain containment relation.
func containGrants(grants, roots []semantics.Grant, dm semantics.DomainMap) ([]semantics.Grant, string) {
	kept := make([]semantics.Grant, 0, len(grants))
	reasons := make([]string, 0, len(grants))
	for _, g := range grants {
		okAny := false
		reason := ""
		for _, r := range roots {
			r := semantics.ContainsWithDomains(r, g, dm, dm)
			if r.Contains {
				okAny = true
				break
			}
			if reason == "" {
				reason = r.Reason
			}
		}
		if okAny {
			kept = append(kept, g)
		} else {
			reasons = append(reasons, reason)
		}
	}
	if len(kept) > 0 {
		return kept, ""
	}
	return nil, fmt.Sprintf("no grant is contained by the root authority (%s)", strings.Join(reasons, ","))
}

// domainMapFor builds the CLC-1.19 domain map for one capability from the
// declaration.  A nil declaration yields shape inference, which is the CLC
// default.
func domainMapFor(raw []byte, capability string) semantics.DomainMap {
	if len(raw) == 0 {
		return nil
	}
	decl, err := ParseDeclaration(raw)
	if err != nil {
		return nil
	}
	return decl.DomainMap(capability)
}

// checkRootRotation enforces the key-level root rotation rules.
func checkRootRotation(c Confirmation) error {
	signerKey := keyIDOf(c.PublisherCert.RawSubjectPublicKeyInfo)
	inCurrent := containsString(c.Policy.RootKeys, signerKey)
	inNext := containsString(c.Policy.NextRootKeys, signerKey)

	if inNext && !inCurrent {
		return fail(CodeRootSelfAuthorized, "signer %s is only in the proposed next root", signerKey)
	}
	if !inCurrent {
		return fail(CodeRootNoCurrentRoot, "signer %s is not a configured current root key", signerKey)
	}

	// A root rotation is authorized by a threshold of distinct current-root
	// keys, not by the publisher alone.  rootSigners is populated only by
	// ConfirmSigned after detached-signature verification; Confirm refuses the
	// multi-signature case before reaching here.
	signers := c.rootSigners
	if len(signers) == 0 {
		signers = []*x509.Certificate{c.PublisherCert}
	}
	current := make(map[string]bool)
	for _, cert := range signers {
		if cert == nil {
			continue
		}
		k := keyIDOf(cert.RawSubjectPublicKeyInfo)
		if containsString(c.Policy.RootKeys, k) {
			current[k] = true
		}
	}
	if c.Policy.RootThreshold < 1 {
		return fail(CodeRootPolicyMismatch, "policy root_threshold must be >= 1")
	}
	if len(current) < c.Policy.RootThreshold {
		return fail(CodeRootThreshold, "have %d distinct current-root signatures, policy requires %d", len(current), c.Policy.RootThreshold)
	}
	if c.Policy.RootPackageDigest == "" || c.Transition.FromDigest != c.Policy.RootPackageDigest {
		return fail(CodeRootPolicyMismatch, "from_digest %q is not the configured root package %q", c.Transition.FromDigest, c.Policy.RootPackageDigest)
	}
	if c.Policy.NextRootPackageDigest == "" || len(c.Policy.NextRootKeys) == 0 || c.Policy.NextRootThreshold < 1 {
		return fail(CodeRootPolicyMismatch, "policy configures no next root")
	}
	if c.Transition.NextRootPackageDigest != c.Policy.NextRootPackageDigest {
		return fail(CodeRootPolicyMismatch, "transition next root %q, policy next root %q", c.Transition.NextRootPackageDigest, c.Policy.NextRootPackageDigest)
	}
	if c.Transition.NextRootThreshold != c.Policy.NextRootThreshold {
		return fail(CodeRootPolicyMismatch, "transition threshold %d, policy threshold %d", c.Transition.NextRootThreshold, c.Policy.NextRootThreshold)
	}
	if !sameSet(c.Transition.NextRootKeys, c.Policy.NextRootKeys) {
		return fail(CodeRootPolicyMismatch, "transition next root keys differ from the configured next root keys")
	}
	if len(c.Transition.NextRootKeys) < c.Transition.NextRootThreshold {
		return fail(CodeRootThreshold, "next root has %d keys, threshold %d", len(c.Transition.NextRootKeys), c.Transition.NextRootThreshold)
	}
	if c.Policy.NextRootPackageDigest == c.Policy.RootPackageDigest {
		return fail(CodeRootSelfAuthorized, "the proposed next root package is the current root package")
	}
	if c.Transition.ToDigest != c.Policy.NextRootPackageDigest {
		return fail(CodeRootPolicyMismatch, "to_digest %q is not the next root package %q", c.Transition.ToDigest, c.Policy.NextRootPackageDigest)
	}
	return nil
}

// checkState compares the transition with the local registry and enforces
// monotonic generations.
func checkState(c Confirmation, res *ConfirmationResult) error {
	if c.Transition.Action == ActionCreate {
		if len(c.State.History) != 0 || c.State.Generation != 0 || c.State.PackageDigest != "" {
			return fail(CodeStateNotEmpty, "create requires an empty namespace state, head is generation %d", c.State.Generation)
		}
		return nil
	}

	// A fork is a generation already recorded with a different digest. Check it
	// before the from_generation comparison so the reason is specific.
	if d, ok := c.State.digestAt(c.Transition.ToGeneration); ok && d != c.Transition.ToDigest {
		return fail(CodeGenerationFork, "generation %d already holds %s, transition proposes %s", c.Transition.ToGeneration, d, c.Transition.ToDigest)
	}

	if c.Transition.FromGeneration == nil {
		return fail(CodeTransitionShape, "%s requires from_generation", c.Transition.Action)
	}
	if c.State.Generation != *c.Transition.FromGeneration {
		return fail(CodeStateGeneration, "local head generation %d, transition from_generation %d", c.State.Generation, *c.Transition.FromGeneration)
	}
	if c.State.PackageDigest != c.Transition.FromDigest {
		return fail(CodeStateDigest, "local head digest %s, transition from_digest %s", c.State.PackageDigest, c.Transition.FromDigest)
	}
	if c.Transition.ToGeneration != *c.Transition.FromGeneration+1 {
		return fail(CodeStateGeneration, "transition must advance exactly one generation, %d -> %d", *c.Transition.FromGeneration, c.Transition.ToGeneration)
	}
	if head := c.State.HeadOf(); c.Transition.ToGeneration <= head {
		return fail(CodeGenerationRollback, "generation %d is not newer than local head %d", c.Transition.ToGeneration, head)
	}
	if c.Transition.Action == ActionUpdate && c.State.Revision != "" {
		if err := revisionFollows(c.State.Revision, c.Package.Revision, c.Transition.ChangeClass); err != nil {
			return fail(CodeChangeClassInvalid, "%s", err)
		}
	}
	return nil
}

// clockSkew is the tolerated forward error when comparing an artifact
// timestamp to the deployer's replayable clock.
const clockSkew = 5 * time.Minute

// checkFreshness applies the deployer's staleness and validity windows.
func checkFreshness(pkg Package, policy TrustPolicy) error {
	now, err := policyTime(policy)
	if err != nil {
		return err
	}
	var issued time.Time
	if pkg.IssuedAt != "" {
		issued, err = time.Parse(time.RFC3339, pkg.IssuedAt)
		if err != nil {
			return fail(CodePackageShape, "issued_at %q is not RFC3339", pkg.IssuedAt)
		}
		if issued.After(now.Add(clockSkew)) {
			return fail(CodePackageStale, "issued_at %s is in the future of observed_at %s", pkg.IssuedAt, policy.ObservedAt)
		}
	}
	if pkg.ValidUntil != "" {
		vu, err := time.Parse(time.RFC3339, pkg.ValidUntil)
		if err != nil {
			return fail(CodePackageShape, "valid_until %q is not RFC3339", pkg.ValidUntil)
		}
		if !issued.IsZero() && !vu.After(issued) {
			return fail(CodePackageShape, "valid_until %s is not after issued_at %s", pkg.ValidUntil, pkg.IssuedAt)
		}
		if now.After(vu) {
			return fail(CodePackageExpired, "valid_until %s precedes %s", pkg.ValidUntil, policy.ObservedAt)
		}
	}
	if policy.MaxStalenessSeconds > 0 {
		if pkg.IssuedAt == "" {
			return fail(CodePackageStale, "issued_at is required when max_staleness_seconds is set")
		}
		if now.Sub(issued) > time.Duration(policy.MaxStalenessSeconds)*time.Second {
			return fail(CodePackageStale, "package is older than %ds", policy.MaxStalenessSeconds)
		}
	}
	return nil
}

func inputsDigest(res *ConfirmationResult) string {
	d, err := CanonicalDigest(map[string]any{
		"package_digest":               res.PackageDigest,
		"transition_digest":            res.TransitionDigest,
		"management_operation_digest":  res.ManagementOperationDigest,
		"approval_operation_digest":    res.ApprovalOperationDigest,
		"publisher_certificate_digest": res.PublisherCertificateDigest,
		"publisher_key_id":             res.PublisherKeyID,
		"trust_policy_digest":          res.TrustPolicyDigest,
		"registry_state_digest":        res.RegistryStateDigest,
		"revoked_package_digest":       res.RevokedPackageDigest,
		"revocation_reason":            res.RevocationReason,
		"revocation_effective_time":    res.RevocationEffectiveTime,
		"replacement_digest":           res.ReplacementDigest,
		"tombstone_generation":         res.TombstoneGeneration,
	})
	if err != nil {
		return ""
	}
	return d
}

func containsString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		if seen[x] == 0 {
			return false
		}
		seen[x]--
	}
	return true
}
