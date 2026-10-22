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
)

// TestConfirmSignedRootThreshold exercises the case Confirm cannot decide: a
// root rotation whose policy requires two distinct current-root signatures.
// The same package must be refused with one current-root signature and with a
// current-root plus a next-root-only signature, and accepted with two current
// roots.
func TestConfirmSignedRootThreshold(t *testing.T) {
	raw, err := os.ReadFile(corpusPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	var v *vectorSpec
	for i := range c.Vectors {
		if c.Vectors[i].ID == "sa-015" {
			v = &c.Vectors[i]
			break
		}
	}
	if v == nil {
		t.Fatal("sa-015 not found")
	}

	caCert, caKey := newCA(t, "ca-threshold")
	defBytes := mustCanonical(t, mustMap(t, c.Definitions[v.Definition]))
	declBytes := mustCanonical(t, mustMap(t, c.Declarations[v.Declaration]))
	pub := c.Publishers[v.Publisher]
	pubCert, pubKey := newPublisher(t, caCert, caKey, pub)

	polRaw, err := resolveRef(v.Policy, c.Policies)
	if err != nil {
		t.Fatal(err)
	}
	var pol policySpec
	if err := json.Unmarshal(polRaw, &pol); err != nil {
		t.Fatalf("policy: %v", err)
	}
	pol.RootKeys = keyIDs(t, caCert, caKey, pol.RootKeySeeds)
	pol.RootThreshold = 2
	extraCert, extraKey := newPublisher(t, caCert, caKey, publisherSpec{
		Seed:      "root-b",
		Principal: "principal:root-admin",
		HasAIC:    boolPtr(false),
	})
	pol.RootKeys = append(pol.RootKeys, schemeadmin.KeyID(extraCert))
	pol.NextRootKeys = keyIDs(t, caCert, caKey, pol.NextRootKeySeeds)

	pkgMap := mustMap(t, v.Package)
	pkgBytes := mustCanonical(t, pkgMap)
	trMap := mustMap(t, v.Transition)
	if seeds, ok := trMap["next_root_key_seeds"]; ok {
		var names []string
		for _, s := range seeds.([]any) {
			names = append(names, s.(string))
		}
		trMap["next_root_keys"] = keyIDs(t, caCert, caKey, names)
		delete(trMap, "next_root_key_seeds")
	}
	trBytes := mustCanonical(t, trMap)
	var st schemeadmin.RegistryState
	if len(v.State) > 0 {
		stRaw, err := resolveRef(v.State, c.States)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(stRaw, &st); err != nil {
			t.Fatalf("state: %v", err)
		}
	}
	tr, err := schemeadmin.ParseTransition(trBytes)
	if err != nil {
		t.Fatal(err)
	}

	sigA, err := pkcs7.BuildSignedData(pkcs7.OIDData, pkgBytes, pubCert, pubKey, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatal(err)
	}
	sigB, err := pkcs7.BuildSignedData(pkcs7.OIDData, pkgBytes, extraCert, extraKey, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatal(err)
	}
	sigTr, err := pkcs7.BuildSignedData(pkcs7.OIDData, trBytes, pubCert, pubKey, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatal(err)
	}
	nextCert, nextKey := newPublisher(t, caCert, caKey, publisherSpec{
		Seed:      "next-a",
		Principal: "principal:root-admin",
		HasAIC:    boolPtr(false),
	})
	sigNext, err := pkcs7.BuildSignedData(pkcs7.OIDData, pkgBytes, nextCert, nextKey, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatal(err)
	}

	base := schemeadmin.SignedConfirmation{
		PackageBytes:         pkgBytes,
		TransitionBytes:      trBytes,
		TransitionSignatures: [][]byte{sigTr},
		Definition:           defBytes,
		Declaration:          declBytes,
		Roots:                []*x509.Certificate{caCert},
		State:                st,
		Policy:               pol.TrustPolicy,
	}
	t.Run("two current roots", func(t *testing.T) {
		c := base
		c.Signatures = [][]byte{sigA, sigB}
		res, err := schemeadmin.ConfirmSigned(c)
		if err != nil {
			t.Fatalf("ConfirmSigned: %v", err)
		}
		if res.Verdict != schemeadmin.VerdictAccept {
			t.Fatalf("verdict %q, want accept", res.Verdict)
		}
	})
	t.Run("one current root", func(t *testing.T) {
		c := base
		c.Signatures = [][]byte{sigA}
		_, err := schemeadmin.ConfirmSigned(c)
		if code := schemeadmin.CodeOf(err); code != schemeadmin.CodeRootThreshold {
			t.Fatalf("code %q, want %q (%v)", code, schemeadmin.CodeRootThreshold, err)
		}
	})
	t.Run("next-only signer does not count", func(t *testing.T) {
		c := base
		c.Signatures = [][]byte{sigA, sigNext}
		_, err := schemeadmin.ConfirmSigned(c)
		if code := schemeadmin.CodeOf(err); code != schemeadmin.CodeRootThreshold {
			t.Fatalf("code %q, want %q (%v)", code, schemeadmin.CodeRootThreshold, err)
		}
	})
	t.Run("missing transition signature is rejected", func(t *testing.T) {
		c := base
		c.Signatures = [][]byte{sigA}
		c.TransitionSignatures = nil
		_, err := schemeadmin.ConfirmSigned(c)
		if code := schemeadmin.CodeOf(err); code != schemeadmin.CodeTransitionSignatureMissing {
			t.Fatalf("code %q, want %q (%v)", code, schemeadmin.CodeTransitionSignatureMissing, err)
		}
	})
	t.Run("transition signed by a non-publisher is rejected", func(t *testing.T) {
		otherTr, err := pkcs7.BuildSignedData(pkcs7.OIDData, trBytes, extraCert, extraKey, []*x509.Certificate{caCert})
		if err != nil {
			t.Fatal(err)
		}
		c := base
		c.Signatures = [][]byte{sigA}
		c.TransitionSignatures = [][]byte{otherTr}
		_, err = schemeadmin.ConfirmSigned(c)
		if code := schemeadmin.CodeOf(err); code != schemeadmin.CodeTransitionSignatureMissing {
			t.Fatalf("code %q, want %q (%v)", code, schemeadmin.CodeTransitionSignatureMissing, err)
		}
	})
	t.Run("legacy Confirm is fail-closed", func(t *testing.T) {
		pkg, err := schemeadmin.ParsePackage(pkgBytes)
		if err != nil {
			t.Fatal(err)
		}
		_, err = schemeadmin.Confirm(schemeadmin.Confirmation{
			Package:       pkg,
			Transition:    tr,
			Definition:    defBytes,
			Declaration:   declBytes,
			PublisherCert: pubCert,
			Roots:         []*x509.Certificate{caCert},
			State:         st,
			Policy:        pol.TrustPolicy,
		})
		if code := schemeadmin.CodeOf(err); code != schemeadmin.CodeSignatureMissing {
			t.Fatalf("code %q, want %q (%v)", code, schemeadmin.CodeSignatureMissing, err)
		}
	})
	t.Run("forged signature is rejected", func(t *testing.T) {
		c := base
		bad := append([]byte(nil), sigA...)
		bad[len(bad)-1] ^= 0xff
		c.Signatures = [][]byte{bad}
		_, err := schemeadmin.ConfirmSigned(c)
		if code := schemeadmin.CodeOf(err); code != schemeadmin.CodeSignatureInvalid {
			t.Fatalf("code %q, want %q (%v)", code, schemeadmin.CodeSignatureInvalid, err)
		}
	})
	t.Run("missing signature is rejected", func(t *testing.T) {
		c := base
		_, err := schemeadmin.ConfirmSigned(c)
		if code := schemeadmin.CodeOf(err); code != schemeadmin.CodeSignatureMissing {
			t.Fatalf("code %q, want %q (%v)", code, schemeadmin.CodeSignatureMissing, err)
		}
	})
}

func boolPtr(v bool) *bool { return &v }
