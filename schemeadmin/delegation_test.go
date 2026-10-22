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

func signedDelegationFixture(t *testing.T) (schemeadmin.Delegation, []byte, []byte, *x509.Certificate, []*x509.Certificate, *schemeadmin.TrustPolicy) {
	t.Helper()
	decl, err := os.ReadFile(publishedSchemeFile(t, "clc-declaration.json"))
	if err != nil {
		t.Fatal(err)
	}
	parentParams := map[string]any{
		"namespace": "/std/payments-v1", "change_class": []string{"patch"},
		"major": 1, "clc_revision": []string{"CLC-1.19"},
	}
	caCert, caKey := newCA(t, "delegation-ca")
	cert, key := newPublisher(t, caCert, caKey, publisherSpec{
		Seed:      "delegation-publisher",
		Principal: "principal:delegator",
		Capabilities: []capSpec{{
			SchemeID:     schemeadmin.SchemeID,
			CapabilityID: schemeadmin.CapDelegate,
			Parameters:   parentParams,
		}},
	})
	d := schemeadmin.Delegation{
		Delegator: "principal:delegator",
		Grantee:   "principal:delegate",
		Parent: semantics.Grant{
			ID:     schemeadmin.FullCapabilityID(schemeadmin.CapUpdate),
			Params: parentParams,
		},
		Child: semantics.Grant{
			ID:     schemeadmin.FullCapabilityID(schemeadmin.CapUpdate),
			Params: parentParams,
		},
	}
	raw, err := semantics.CanonicalJSON(d)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, raw, cert, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := &schemeadmin.TrustPolicy{
		AdministrationDeclaration: decl,
		RootGrants:                []semantics.Grant{d.Parent},
		ObservedAt:                "2026-10-22T00:00:00Z",
	}
	return d, raw, sig, cert, []*x509.Certificate{caCert}, policy
}

func TestValidateSignedDelegation(t *testing.T) {
	_, raw, sig, cert, roots, policy := signedDelegationFixture(t)
	if err := schemeadmin.ValidateSignedDelegation(raw, sig, roots, *policy); err != nil {
		t.Fatalf("signed delegation rejected: %v", err)
	}
	if err := schemeadmin.ValidateSignedDelegation(append(append([]byte{}, raw...), ' '), sig, roots, *policy); schemeadmin.CodeOf(err) != schemeadmin.CodeSignatureInvalid {
		t.Fatalf("tampered delegation: got %v", err)
	}
	var d schemeadmin.Delegation
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	d.Delegator = "principal:other"
	other, err := semantics.CanonicalJSON(d)
	if err != nil {
		t.Fatal(err)
	}
	otherSig, err := pkcs7.BuildSignedData(pkcs7.OIDData, other, cert, fixtureKey(t, "delegation-publisher"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemeadmin.ValidateSignedDelegation(other, otherSig, roots, *policy); schemeadmin.CodeOf(err) != schemeadmin.CodePublisherMismatch {
		t.Fatalf("wrong delegator: got %v", err)
	}
}
