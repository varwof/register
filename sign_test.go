// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func genTestKeyPair(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Signer", Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
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

func TestSignAndVerifyCapability(t *testing.T) {
	dir := t.TempDir()
	cert, key := genTestKeyPair(t)

	certPath := filepath.Join(dir, "signer.pem")
	keyPath := filepath.Join(dir, "signer-key.pem")
	capPath := filepath.Join(dir, "capability.json")
	outputPath := filepath.Join(dir, "capability.json.p7s")

	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0644)

	keyDER, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
	os.WriteFile(capPath, []byte(`{"id":"test:cap1"}`), 0644)

	if err := SignCapability(certPath, keyPath, capPath, outputPath); err != nil {
		t.Fatalf("SignCapability: %v", err)
	}

	if !HasSignature(capPath) {
		t.Fatal("expected .p7s file to exist")
	}

	trustRoots := []*x509.Certificate{cert}
	if err := VerifyCapabilityPKCS7(capPath, trustRoots); err != nil {
		t.Fatalf("VerifyCapabilityPKCS7: %v", err)
	}
}

func TestSignCapability_MissingFile(t *testing.T) {
	err := SignCapability("/nonexistent/cert.pem", "/nonexistent/key.pem", "/nonexistent/cap.json", "")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestHasSignature_NoFile(t *testing.T) {
	if HasSignature("/nonexistent/file.json") {
		t.Fatal("expected false for nonexistent file")
	}
}

func TestLoadCertFile_Valid(t *testing.T) {
	dir := t.TempDir()
	cert, _ := genTestKeyPair(t)
	certPath := filepath.Join(dir, "cert.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0644)

	certs, err := LoadCertFile(certPath)
	if err != nil {
		t.Fatalf("LoadCertFile: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "Test Signer" {
		t.Errorf("wrong cert CN: %s", certs[0].Subject.CommonName)
	}
}

func TestLoadCertFile_MissingFile(t *testing.T) {
	_, err := LoadCertFile("/nonexistent/cert.pem")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadCertFile_NoCerts(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "empty.pem")
	os.WriteFile(f, []byte("not a cert"), 0644)
	_, err := LoadCertFile(f)
	if err == nil {
		t.Fatal("expected error for no valid certs")
	}
}

func TestLoadTrustRoots_File(t *testing.T) {
	dir := t.TempDir()
	cert, _ := genTestKeyPair(t)
	f := filepath.Join(dir, "root.pem")
	os.WriteFile(f, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0644)

	roots, err := LoadTrustRoots(f)
	if err != nil {
		t.Fatalf("LoadTrustRoots: %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("expected 1 root, got %d", len(roots))
	}
}

func TestLoadTrustRoots_Dir(t *testing.T) {
	dir := t.TempDir()
	cert1, _ := genTestKeyPair(t)
	cert2, _ := genTestKeyPair(t)

	os.WriteFile(filepath.Join(dir, "a.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw}), 0644)
	os.WriteFile(filepath.Join(dir, "b.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw}), 0644)
	os.WriteFile(filepath.Join(dir, "skip.txt"), []byte("not cert"), 0644)

	roots, err := LoadTrustRoots(dir)
	if err != nil {
		t.Fatalf("LoadTrustRoots: %v", err)
	}
	if len(roots) != 2 {
		t.Fatalf("expected 2 roots, got %d", len(roots))
	}
}

func TestLoadTrustRoots_Nonexistent(t *testing.T) {
	_, err := LoadTrustRoots("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestGetSignerCert_Valid(t *testing.T) {
	dir := t.TempDir()
	cert, key := genTestKeyPair(t)

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	capPath := filepath.Join(dir, "cap.json")
	p7sPath := filepath.Join(dir, "cap.json.p7s")

	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0644)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
	os.WriteFile(capPath, []byte(`{"id":"test"}`), 0644)

	if err := SignCapability(certPath, keyPath, capPath, p7sPath); err != nil {
		t.Fatalf("SignCapability: %v", err)
	}

	signerCert, err := GetSignerCert(p7sPath)
	if err != nil {
		t.Fatalf("GetSignerCert: %v", err)
	}
	if signerCert.Subject.CommonName != "Test Signer" {
		t.Errorf("wrong signer CN: %s", signerCert.Subject.CommonName)
	}
}

func TestGetSignerCert_MissingFile(t *testing.T) {
	_, err := GetSignerCert("/nonexistent/file.p7s")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestGetSignerCert_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "bad.p7s")
	os.WriteFile(f, []byte("not-pem"), 0644)
	_, err := GetSignerCert(f)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}
