// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import (
	"crypto/x509"
	"strings"

	"github.com/varwof/pkcs7"

	"github.com/varwof/register/semantics"
)

// Delegation is a proposed sub-grant of administration authority from one
// principal to another.  The parent grant is the delegator's own grant; the
// child grant is what it proposes to hand on.
//
// Delegation is a grant relation, not a package transition: it never carries a
// transition artifact and it never mints a package.
type Delegation struct {
	// Delegator is optional in the pure relation, but a signed delegation must
	// name the principal whose AIC key signed it.
	Delegator string          `json:"delegator,omitempty"`
	Grantee   string          `json:"grantee"`
	Parent    semantics.Grant `json:"parent"`
	Child     semantics.Grant `json:"child"`
}

// administrationCapabilities is the closed set a delegation may name.
// `scheme:verify` is deliberately absent: verification is unprivileged, so
// there is nothing to delegate.
var administrationCapabilities = map[string]bool{
	CapCreate:     true,
	CapUpdate:     true,
	CapRevoke:     true,
	CapDelegate:   true,
	CapRootRotate: true,
	CapApprove:    true,
}

// ValidateDelegation checks that a child grant never exceeds the delegator's
// own grant, using the CLC-1.19 declared-domain containment relation.
//
// The relation is CLC containment, so an identical grant is not wider and is
// accepted.  What is refused is any widening: a broader namespace, an added
// change class, a higher major bound, an added CLC revision, or a capability the
// delegator does not hold.
func ValidateDelegation(d Delegation, policy TrustPolicy) error {
	if d.Delegator != "" && !principalRe.MatchString(d.Delegator) {
		return fail(CodeDelegationNotContained, "delegator %q is not principal:<id>", d.Delegator)
	}
	if !principalRe.MatchString(d.Grantee) {
		return fail(CodeDelegationNotContained, "grantee %q is not principal:<id>", d.Grantee)
	}
	if err := checkAdministrationGrant(d.Parent); err != nil {
		return err
	}
	if err := checkAdministrationGrant(d.Child); err != nil {
		return err
	}

	capability, ok := capabilityOf(d.Child.ID)
	if !ok {
		return fail(CodeDelegationNotContained, "child %q is not a %s capability", d.Child.ID, SchemeID)
	}
	if strings.HasSuffix(capability, "*") {
		return fail(CodeDelegationNotContained, "child must name a concrete capability, not a wildcard")
	}
	dm := domainMapFor(policy.AdministrationDeclaration, capability)

	// The delegator must itself be inside the configured root authority.
	if len(policy.RootGrants) == 0 {
		return fail(CodeAuthorityNotContained, "policy configures no root authority")
	}
	parentOK := false
	for _, root := range policy.RootGrants {
		if r := semantics.ContainsWithDomains(root, d.Parent, dm, dm); r.Contains {
			parentOK = true
			break
		}
	}
	if !parentOK {
		return fail(CodeAuthorityNotContained, "delegator grant %q is outside the root authority", d.Parent.ID)
	}

	r := semantics.ContainsWithDomains(d.Parent, d.Child, dm, dm)
	if !r.Contains {
		return fail(CodeDelegationNotContained, "child %q is not contained by parent %q: %s", d.Child.ID, d.Parent.ID, r.Reason)
	}
	return nil
}

// BuildDelegationOperation builds the CLC operation a delegator must be
// authorized for.  It is the parent capability applied to the child's declared
// dimensions.
func BuildDelegationOperation(d Delegation) (semantics.Operation, error) {
	if err := checkAdministrationGrant(d.Child); err != nil {
		return semantics.Operation{}, err
	}
	return semantics.Operation{ID: d.Child.ID, Params: copyParams(d.Child.Params)}, nil
}

// checkAdministrationGrant rejects a grant that names a capability outside the
// closed administration set.
func checkAdministrationGrant(g semantics.Grant) error {
	capability, ok := capabilityOf(g.ID)
	if !ok {
		return fail(CodeDelegationNotContained, "%q is not a %s capability", g.ID, SchemeID)
	}
	if !administrationCapabilities[capability] {
		return fail(CodeDelegationNotContained, "%q is not an administration capability", g.ID)
	}
	return nil
}

func copyParams(p map[string]any) map[string]any {
	out := make(map[string]any, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

// ValidateSignedDelegation verifies a detached PKCS#7 signature over the exact
// delegation bytes, checks the signer chain/AIC, binds an optional delegator
// principal, and requires the signer's AIC to actually hold the parent grant.
// It then applies the same CLC containment relation as ValidateDelegation.
func ValidateSignedDelegation(raw, signature []byte, roots []*x509.Certificate, policy TrustPolicy) error {
	if len(raw) > maxArtifactBytes {
		return fail(CodeDelegationNotContained, "delegation is %d bytes, limit is %d", len(raw), maxArtifactBytes)
	}
	if len(signature) == 0 {
		return fail(CodeSignatureMissing, "detached delegation signature is required")
	}
	cert, err := pkcs7.VerifyDetached(signature, raw)
	if err != nil {
		return fail(CodeSignatureInvalid, "%s", err)
	}
	if cert == nil {
		return fail(CodeSignatureInvalid, "delegation signature recovered no certificate")
	}
	now, err := policyTime(policy)
	if err != nil {
		return err
	}
	aic, err := verifyCertificate(cert, roots, now)
	if err != nil {
		return err
	}
	var d Delegation
	if err := decodeClosed(raw, &d); err != nil {
		return fail(CodeDelegationNotContained, "delegation: %s", err)
	}
	if d.Delegator != "" {
		want := strings.TrimPrefix(d.Delegator, "principal:")
		id := aic.PrincipalUid.Identifier
		realm := aic.PrincipalUid.Realm
		if want != id && want != realm+":"+id {
			return fail(CodePublisherMismatch, "delegation names delegator %q, AIC names %q", d.Delegator, realm+":"+id)
		}
	}
	capability, ok := capabilityOf(d.Parent.ID)
	if !ok {
		return fail(CodeDelegationNotContained, "parent %q is not a %s capability", d.Parent.ID, SchemeID)
	}
	dm := domainMapFor(policy.AdministrationDeclaration, capability)
	// A delegator proves authority with its scheme:delegate grant; that grant's
	// parameters are the delegation scope.  Compare those parameters against the
	// parent grant, not against a scheme:update grant it may not hold.
	parentHeld := false
	for _, grant := range grantsFor(aic, FullCapabilityID(CapDelegate)) {
		grant.ID = d.Parent.ID
		if semantics.ContainsWithDomains(grant, d.Parent, dm, dm).Contains {
			parentHeld = true
			break
		}
	}
	if !parentHeld {
		return fail(CodeAuthorityNotContained, "signer AIC does not hold scheme:delegate authority for parent %q", d.Parent.ID)
	}
	return ValidateDelegation(d, policy)
}
