// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/varwof/pkcs7"
	pki "github.com/varwof/types"

	"github.com/varwof/register/schemeadmin"
)

// TestCheckAcceptsValidCreate drives the CLI exactly as a deployer would:
// files on disk, detached PKCS#7 over the package bytes, then the confirmation
// path.  It is the end-to-end companion to the corpus runner.
func TestCheckAcceptsValidCreate(t *testing.T) {
	dir := t.TempDir()
	defPath := findFixture(t, "../../../capability/data/std/payments-v1/v1.json", "../../capability/data/std/payments-v1/v1.json")
	declPath := findFixture(t, "../../../capability/data/std/payments-v1/clc-declaration.json", "../../capability/data/std/payments-v1/clc-declaration.json")
	adminDeclPath := findFixture(t, "../../../capability/data/varwof/scheme-admin-v1/clc-declaration.json", "../../capability/data/varwof/scheme-admin-v1/clc-declaration.json")

	defBytes, err := os.ReadFile(defPath)
	if err != nil {
		t.Fatal(err)
	}
	declBytes, err := os.ReadFile(declPath)
	if err != nil {
		t.Fatal(err)
	}
	adminDeclBytes, err := os.ReadFile(adminDeclPath)
	if err != nil {
		t.Fatal(err)
	}

	pkg := map[string]any{
		"@version":           "CLC-SCHEME-PACKAGE-v1",
		"scheme":             "std/payments-v1",
		"revision":           "1.0",
		"definition_digest":  schemeadmin.Digest(defBytes),
		"declaration_digest": schemeadmin.Digest(declBytes),
		"clc_revision":       "CLC-1.19",
		"change_class":       "major",
		"publisher":          "principal:payments-scheme-admin",
		"generation":         1,
	}
	pkgBytes := mustJSON(t, pkg)

	tr := map[string]any{
		"@version":            "CLC-SCHEME-TRANSITION-v1",
		"action":              "create",
		"scheme":              "std/payments-v1",
		"namespace":           "/std/payments-v1",
		"to_generation":       1,
		"to_digest":           schemeadmin.Digest(pkgBytes),
		"change_class":        "major",
		"target_clc_revision": "CLC-1.19",
	}
	trBytes := mustJSON(t, tr)

	caCert, caKey := makeCA(t)
	pubCert, pubKey := makePublisher(t, caCert, caKey, "principal:payments-scheme-admin",
		[]pki.Capability{{
			SchemeId:     schemeadmin.SchemeID,
			CapabilityId: "scheme:create",
			Parameters: mustJSON(t, map[string]any{
				"namespace":    "/std/payments-v1",
				"change_class": []string{"major"},
				"major":        3,
				"clc_revision": []string{"CLC-1.19"},
			}),
		}})

	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, pkgBytes, pubCert, pubKey, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	trSig, err := pkcs7.BuildSignedData(pkcs7.OIDData, trBytes, pubCert, pubKey, []*x509.Certificate{caCert})
	if err != nil {
		t.Fatalf("sign transition: %v", err)
	}

	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	pkgPath := write("pkg.json", pkgBytes)
	trPath := write("tr.json", trBytes)
	defPath2 := write("def.json", defBytes)
	declPath2 := write("decl.json", declBytes)
	sigPath := write("pkg.json.p7s", pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: sig}))
	trSigPath := write("tr.json.p7s", pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: trSig}))
	rootsPath := write("roots.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))

	var adminDecl any
	if err := json.Unmarshal(adminDeclBytes, &adminDecl); err != nil {
		t.Fatal(err)
	}
	policy := map[string]any{
		"administration_declaration": adminDecl,
		"root_package_digest":        schemeadmin.Digest(pkgBytes),
		"root_keys":                  []string{schemeadmin.KeyID(pubCert)},
		"root_threshold":             1,
		"root_grants": []map[string]any{
			{
				"id": schemeadmin.FullCapabilityID("scheme:create"),
				"params": map[string]any{
					"namespace":    "/std",
					"change_class": []string{"patch", "minor", "major"},
					"major":        3,
					"clc_revision": []string{"CLC-1.19"},
				},
			},
		},
		"supported_clc_revisions": []string{"CLC-1.19"},
		"namespace_prefixes":      []string{"/std"},
		"max_major":               3,
		"observed_at":             "2026-10-22T00:00:00Z",
	}
	policyPath := write("policy.json", mustJSON(t, policy))

	accepted, err := runConfirm([]string{
		"--package", pkgPath,
		"--transition", trPath,
		"--definition", defPath2,
		"--declaration", declPath2,
		"--signature", sigPath,
		"--transition-signature", trSigPath,
		"--trust", rootsPath,
		"--policy", policyPath,
	}, "")
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if !accepted {
		t.Fatal("expected the CLI to accept a valid create")
	}
}

func findFixture(t *testing.T, candidates ...string) string {
	t.Helper()
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skipf("fixture not found (capability checkout absent): %v", candidates)
	return ""
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func makeCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cli fixture CA"},
		NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func makePublisher(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, principal string, caps []pki.Capability) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyHash := sha256.Sum256(spki)
	id := principal[len("principal:"):]
	aic := pki.AIC{
		Version:      1,
		AgentId:      "agent:" + id,
		PrincipalUid: pki.PrincipalUid{Realm: "varwof", Identifier: id, KeyHash: keyHash[:]},
		Capabilities: caps,
		DelegationAuthorization: pki.DelegationAuthorization{
			Reason:             pki.Reason{ReasonCode: "scheme-publication", Description: "publish a scheme package"},
			RequestedLifetime:  3600,
			Timestamp:          time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC),
			Nonce:              make([]byte, 32),
			SignatureAlgorithm: pki.SigAlgoToOID(x509.ECDSAWithSHA256),
			SignatureValue:     []byte{0x01},
		},
	}
	aicDER, err := asn1.Marshal(aic)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: principal},
		NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{{Id: pki.OIDAIC, Value: aicDER}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}
