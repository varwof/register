// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin_test

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"testing"

	"github.com/varwof/pkcs7"

	"github.com/varwof/register/schemeadmin"
	"github.com/varwof/register/semantics"
)

func TestSignedApprovals(t *testing.T) {
	raw, err := os.ReadFile(corpusPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	var v *vectorSpec
	for i := range c.Vectors {
		if c.Vectors[i].ID == "sa-001" {
			v = &c.Vectors[i]
			break
		}
	}
	if v == nil {
		t.Fatal("sa-001 not found")
	}
	caCert, caKey := newCA(t, "ca-approval")
	defBytes := mustCanonical(t, mustMap(t, c.Definitions[v.Definition]))
	declBytes := mustCanonical(t, mustMap(t, c.Declarations[v.Declaration]))
	pubCert, pubKey := newPublisher(t, caCert, caKey, c.Publishers[v.Publisher])

	pkgBytes := mustCanonical(t, mustMap(t, v.Package))
	trBytes := mustCanonical(t, mustMap(t, v.Transition))
	pkg, err := schemeadmin.ParsePackage(pkgBytes)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := schemeadmin.ParseTransition(trBytes)
	if err != nil {
		t.Fatal(err)
	}
	pkgDigest, err := schemeadmin.PackageDigest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	trDigest, err := schemeadmin.TransitionDigest(tr)
	if err != nil {
		t.Fatal(err)
	}

	approveParams := map[string]any{
		"namespace":         tr.Namespace,
		"package_digest":    pkgDigest,
		"transition_digest": trDigest,
		"clc_revision":      []string{"CLC-1.19"},
	}
	approverCert, approverKey := newPublisher(t, caCert, caKey, publisherSpec{
		Seed:      "approver-a",
		Principal: "principal:approver-a",
		Capabilities: []capSpec{{
			SchemeID:     schemeadmin.SchemeID,
			CapabilityID: "scheme:approve",
			Parameters:   approveParams,
		}},
	})

	polRaw, err := resolveRef(v.Policy, c.Policies)
	if err != nil {
		t.Fatal(err)
	}
	var pol policySpec
	if err := json.Unmarshal(polRaw, &pol); err != nil {
		t.Fatal(err)
	}
	pol.ApprovalThreshold = 1
	pol.RootGrants = append(pol.RootGrants, semantics.Grant{
		ID:     schemeadmin.FullCapabilityID("scheme:approve"),
		Params: approveParams,
	})
	pol.RootKeys = keyIDs(t, caCert, caKey, pol.RootKeySeeds)
	pol.NextRootKeys = keyIDs(t, caCert, caKey, pol.NextRootKeySeeds)

	payload, err := schemeadmin.ApprovalSigningBytes(pkg, tr)
	if err != nil {
		t.Fatal(err)
	}
	approvalSig, err := pkcs7.BuildSignedData(pkcs7.OIDData, payload, approverCert, approverKey, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatal(err)
	}
	approval := schemeadmin.Approval{
		PackageDigest:    pkgDigest,
		TransitionDigest: trDigest,
		Approver:         "principal:approver-a",
		Signature:        approvalSig,
	}

	pkgSig, err := pkcs7.BuildSignedData(pkcs7.OIDData, pkgBytes, pubCert, pubKey, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatal(err)
	}
	trSig, err := pkcs7.BuildSignedData(pkcs7.OIDData, trBytes, pubCert, pubKey, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatal(err)
	}
	base := schemeadmin.SignedConfirmation{
		PackageBytes:         pkgBytes,
		Signatures:           [][]byte{pkgSig},
		TransitionBytes:      trBytes,
		TransitionSignatures: [][]byte{trSig},
		Definition:           defBytes,
		Declaration:          declBytes,
		Roots:                []*x509.Certificate{caCert},
		State: schemeadmin.RegistryState{
			Approvals: []schemeadmin.Approval{approval},
		},
		Policy: pol.TrustPolicy,
	}

	t.Run("valid signed approval", func(t *testing.T) {
		res, err := schemeadmin.ConfirmSigned(base)
		if err != nil {
			t.Fatalf("ConfirmSigned: %v", err)
		}
		if res.Verdict != schemeadmin.VerdictAccept {
			t.Fatalf("verdict %q", res.Verdict)
		}
	})
	t.Run("unsigned approval", func(t *testing.T) {
		bad := base
		a := approval
		a.Signature = nil
		bad.State.Approvals = []schemeadmin.Approval{a}
		if _, err := schemeadmin.ConfirmSigned(bad); schemeadmin.CodeOf(err) != schemeadmin.CodeApprovalInvalid {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("duplicate approver key", func(t *testing.T) {
		secondCert, secondKey := newPublisher(t, caCert, caKey, publisherSpec{
			Seed:      "approver-a", // same key as approverCert
			Principal: "principal:approver-b",
			Capabilities: []capSpec{{
				SchemeID:     schemeadmin.SchemeID,
				CapabilityID: "scheme:approve",
				Parameters:   approveParams,
			}},
		})
		secondSig, err := pkcs7.BuildSignedData(pkcs7.OIDData, payload, secondCert, secondKey, []*x509.Certificate{caCert})
		if err != nil {
			t.Fatal(err)
		}
		second := schemeadmin.Approval{
			PackageDigest:    pkgDigest,
			TransitionDigest: trDigest,
			Approver:         "principal:approver-b",
			Signature:        secondSig,
		}
		bad := base
		bad.State.Approvals = []schemeadmin.Approval{approval, second}
		bad.Policy.ApprovalThreshold = 2
		if _, err := schemeadmin.ConfirmSigned(bad); schemeadmin.CodeOf(err) != schemeadmin.CodeApprovalInvalid {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("duplicate approver", func(t *testing.T) {
		bad := base
		bad.State.Approvals = []schemeadmin.Approval{approval, approval}
		if _, err := schemeadmin.ConfirmSigned(bad); schemeadmin.CodeOf(err) != schemeadmin.CodeApprovalInvalid {
			t.Fatalf("got %v", err)
		}
	})
}
