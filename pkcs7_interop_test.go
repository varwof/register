// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// PKCS#7 interop with openssl.  The forked pkcs7 package and the verifier are
// our own code, so "we sign, we verify" proves nothing about conformance with
// the standard.  openssl is the independent oracle: testdata/pkcs7-interop/
// carries a committed openssl-produced detached signature that the Go verifier
// must accept (no openssl needed, runs on every platform), and when an OpenSSL
// 3 binary is on PATH the reverse direction is generated live (Go signs,
// openssl verifies).

func opensslBin(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not on PATH: skipping live PKCS#7 interop")
	}
	out, _ := exec.Command(bin, "version").CombinedOutput()
	if !strings.Contains(string(out), "OpenSSL") {
		// LibreSSL (the default /usr/bin/openssl on macOS runners) lacks
		// `req -addext` and parts of `cms`; the committed fixture still runs.
		t.Skipf("openssl is not OpenSSL (%s): skipping live PKCS#7 interop",
			strings.TrimSpace(string(out)))
	}
	return bin
}

func runOpenSSL(t *testing.T, bin string, args ...string) {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func loadOneCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s: not a PEM certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return cert
}

// stageNextTo places a copy of data at dir/name and the given p7s beside it as
// dir/name.p7s, mirroring the layout the verifier reads.
func stageNextTo(t *testing.T, dir, name string, data, p7s []byte) string {
	t.Helper()
	content := filepath.Join(dir, name)
	if err := os.WriteFile(content, data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(content+".p7s", p7s, 0644); err != nil {
		t.Fatal(err)
	}
	return content
}

// TestPKCS7InteropFixtureOpenSSLSignature pins the committed openssl-produced
// detached PKCS#7: the Go verifier MUST accept it, and MUST reject it when the
// content is tampered with, when the only trust root is an unrelated CA, and
// when no trust root is supplied (the R1 fail-open shape).  This runs without
// openssl, so the interop contract is regression-checked on every runner.
func TestPKCS7InteropFixtureOpenSSLSignature(t *testing.T) {
	fixture := filepath.Join("testdata", "pkcs7-interop")
	content, err := os.ReadFile(filepath.Join(fixture, "content.json"))
	if err != nil {
		t.Fatal(err)
	}
	p7s, err := os.ReadFile(filepath.Join(fixture, "openssl.p7s"))
	if err != nil {
		t.Fatal(err)
	}
	root := loadOneCert(t, filepath.Join(fixture, "root.pem"))

	staged := stageNextTo(t, t.TempDir(), "content.json", content, p7s)
	if err := VerifyCapabilityPKCS7(staged, []*x509.Certificate{root}); err != nil {
		t.Fatalf("Go verifier rejected the committed openssl PKCS#7 signature: %v", err)
	}

	tampered := append(append([]byte{}, content...), ' ')
	bad := stageNextTo(t, t.TempDir(), "content.json", tampered, p7s)
	if err := VerifyCapabilityPKCS7(bad, []*x509.Certificate{root}); err == nil {
		t.Fatal("tampered content verified against the openssl signature")
	}

	unrelated := loadOneCert(t, filepath.Join(fixture, "unrelated-ca.pem"))
	wrong := stageNextTo(t, t.TempDir(), "content.json", content, p7s)
	if err := VerifyCapabilityPKCS7(wrong, []*x509.Certificate{unrelated}); err == nil {
		t.Fatal("signature verified against an unrelated trust root")
	}

	noroot := stageNextTo(t, t.TempDir(), "content.json", content, p7s)
	if err := VerifyCapabilityPKCS7(noroot, nil); err == nil {
		t.Fatal("signature verified without any trust root (R1 fail-open)")
	}
}

// genOpenSSLChain mints a fresh root CA and a codeSigning leaf with openssl.
func genOpenSSLChain(t *testing.T, bin, dir string) (rootPath, signerPath, signerKeyPath string) {
	t.Helper()
	rootKey := filepath.Join(dir, "root.key.pem")
	rootPath = filepath.Join(dir, "root.pem")
	signerKeyPath = filepath.Join(dir, "signer.key.pem")
	signerCSR := filepath.Join(dir, "signer.csr")
	signerPath = filepath.Join(dir, "signer.pem")

	runOpenSSL(t, bin, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", rootKey)
	runOpenSSL(t, bin, "req", "-x509", "-new", "-key", rootKey, "-sha256", "-days", "3650",
		"-subj", "/O=varwof test/CN=varwof interop test root CA",
		"-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=critical,keyCertSign,cRLSign",
		"-out", rootPath)

	runOpenSSL(t, bin, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", signerKeyPath)
	runOpenSSL(t, bin, "req", "-new", "-key", signerKeyPath,
		"-subj", "/O=varwof test/CN=varwof interop test signer", "-out", signerCSR)

	ext := filepath.Join(dir, "signer.ext")
	if err := os.WriteFile(ext, []byte(
		"basicConstraints=critical,CA:FALSE\n"+
			"keyUsage=critical,digitalSignature\n"+
			"extendedKeyUsage=codeSigning\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runOpenSSL(t, bin, "x509", "-req", "-in", signerCSR, "-sha256", "-days", "3650",
		"-CA", rootPath, "-CAkey", rootKey,
		"-CAserial", filepath.Join(dir, "root.srl"), "-CAcreateserial",
		"-extfile", ext,
		"-out", signerPath)
	return rootPath, signerPath, signerKeyPath
}

// TestPKCS7InteropOpenSSLSignsGoVerifies signs with openssl cms and requires
// the Go verifier to accept the result.
func TestPKCS7InteropOpenSSLSignsGoVerifies(t *testing.T) {
	bin := opensslBin(t)
	dir := t.TempDir()
	rootPath, signerPath, signerKeyPath := genOpenSSLChain(t, bin, dir)

	content := filepath.Join(dir, "capability.json")
	if err := os.WriteFile(content, []byte(`{"scheme_id":"std/database-v1"}`), 0644); err != nil {
		t.Fatal(err)
	}
	runOpenSSL(t, bin, "cms", "-sign", "-binary", "-in", content,
		"-signer", signerPath, "-inkey", signerKeyPath,
		"-certfile", rootPath, "-outform", "PEM", "-out", content+".p7s")

	root := loadOneCert(t, rootPath)
	if err := VerifyCapabilityPKCS7(content, []*x509.Certificate{root}); err != nil {
		t.Fatalf("Go verifier rejected an openssl-signed PKCS#7: %v", err)
	}

	otherDir := t.TempDir()
	otherRoot, _, _ := genOpenSSLChain(t, bin, otherDir)
	if err := VerifyCapabilityPKCS7(content, []*x509.Certificate{loadOneCert(t, otherRoot)}); err == nil {
		t.Fatal("signature verified against an unrelated trust root")
	}
}

// TestPKCS7InteropGoSignsOpenSSLVerifies requires openssl cms to accept a
// signature produced by SignCapability.
func TestPKCS7InteropGoSignsOpenSSLVerifies(t *testing.T) {
	bin := opensslBin(t)
	dir := t.TempDir()
	rootPath, signerPath, signerKeyPath := genOpenSSLChain(t, bin, dir)

	content := filepath.Join(dir, "capability.json")
	if err := os.WriteFile(content, []byte(`{"scheme_id":"std/database-v1"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := SignCapability(signerPath, signerKeyPath, content, ""); err != nil {
		t.Fatalf("SignCapability: %v", err)
	}
	if _, err := os.Stat(content + ".p7s"); err != nil {
		t.Fatalf("SignCapability did not write %s.p7s: %v", content, err)
	}

	runOpenSSL(t, bin, "cms", "-verify", "-binary", "-content", content,
		"-in", content+".p7s", "-inform", "PEM",
		"-CAfile", rootPath, "-purpose", "any")

	if err := os.WriteFile(content+".p7s", []byte("not a signature"), 0644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "cms", "-verify", "-binary", "-content", content,
		"-in", content+".p7s", "-inform", "PEM",
		"-CAfile", rootPath, "-purpose", "any").CombinedOutput(); err == nil {
		t.Fatalf("openssl accepted a non-signature; output:\n%s", out)
	}
}
