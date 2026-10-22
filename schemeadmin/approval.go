// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import (
	"strings"
	"time"

	"github.com/varwof/pkcs7"

	"github.com/varwof/register/semantics"
)

// ApprovalSigningBytes is the exact payload an approver signs: the canonical
// scheme:approve operation for this package and transition.  It binds both
// digests, the namespace and the target CLC revision.
func ApprovalSigningBytes(pkg Package, tr Transition) ([]byte, error) {
	op, err := BuildApprovalOperation(pkg, tr)
	if err != nil {
		return nil, err
	}
	return semantics.CanonicalJSON(op)
}

// verifyApprovals verifies every matching approval signature, binds it to the
// signer's AIC principal and key, proves the signer holds scheme:approve inside
// the deployer's root authority, and counts distinct approvers.  An unsigned or
// duplicate approval is an error, never an extra count.
func verifyApprovals(c Confirmation, now time.Time, pkgDigest, trDigest string) (int, error) {
	payload, err := ApprovalSigningBytes(c.Package, c.Transition)
	if err != nil {
		return 0, fail(CodeApprovalInvalid, "%s", err)
	}
	op, err := BuildApprovalOperation(c.Package, c.Transition)
	if err != nil {
		return 0, fail(CodeApprovalInvalid, "%s", err)
	}
	capability, _ := capabilityOf(op.ID)
	dm := domainMapFor(c.Policy.AdministrationDeclaration, capability)
	approvers := make(map[string]bool)
	keys := make(map[string]bool)
	if len(c.State.Approvals) > maxApprovalRecords {
		return 0, fail(CodeApprovalInvalid, "too many approval records (limit %d)", maxApprovalRecords)
	}

	for i, a := range c.State.Approvals {
		if a.PackageDigest != pkgDigest || a.TransitionDigest != trDigest {
			continue
		}
		if len(a.Signature) == 0 {
			return 0, fail(CodeApprovalInvalid, "approval %d has no detached signature", i)
		}
		cert, err := pkcs7.VerifyDetached(a.Signature, payload)
		if err != nil {
			return 0, fail(CodeApprovalInvalid, "approval %d signature: %s", i, err)
		}
		if cert == nil {
			return 0, fail(CodeApprovalInvalid, "approval %d recovered no certificate", i)
		}
		aic, err := verifyCertificate(cert, c.Roots, now)
		if err != nil {
			return 0, fail(CodeApprovalInvalid, "approval %d signer: %s", i, err)
		}
		id := aic.PrincipalUid.Identifier
		realm := aic.PrincipalUid.Realm
		want := strings.TrimPrefix(a.Approver, "principal:")
		if want == "" || (want != id && want != realm+":"+id) {
			return 0, fail(CodeApprovalInvalid, "approval %d names %q, AIC names %q", i, a.Approver, realm+":"+id)
		}

		grants := grantsFor(aic, op.ID)
		if len(grants) == 0 {
			return 0, fail(CodeApprovalInvalid, "approval %d signer holds no %s capability", i, op.ID)
		}
		contained, detail := containGrants(grants, c.Policy.RootGrants, dm)
		if len(contained) == 0 {
			return 0, fail(CodeApprovalInvalid, "approval %d authority is outside the root grants: %s", i, detail)
		}
		if decision := semantics.AuthorizeSetWithDomains(contained, op, dm); decision.Verdict != semantics.VerdictAllow {
			return 0, fail(CodeApprovalInvalid, "approval %d is not authorized by CLC: %s", i, decision.Reason)
		}

		// One principal/key counts once, even with multiple certificates or
		// keys.  Distinct principals that share one key must not satisfy a
		// multi-party threshold.
		principal := realm + ":" + id
		key := keyIDOf(cert.RawSubjectPublicKeyInfo)
		if approvers[principal] {
			return 0, fail(CodeApprovalInvalid, "duplicate approval by %s", principal)
		}
		if keys[key] {
			return 0, fail(CodeApprovalInvalid, "duplicate approval key %s", key)
		}
		approvers[principal] = true
		keys[key] = true
	}
	return len(approvers), nil
}
