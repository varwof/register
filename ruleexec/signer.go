// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

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
	"time"
)

// GenSignerCert creates a self-signed signer certificate and key for
// rule signing (PKCS#7). Returns PEM file paths and the parsed cert.
func GenSignerCert(dir string) (certPath, keyPath string, cert *x509.Certificate, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "rule-exec signer"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", nil, err
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		return "", "", nil, err
	}
	certPath = filepath.Join(dir, "signer.pem")
	keyPath = filepath.Join(dir, "signer.key")
	cb := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", nil, err
	}
	kbPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
	if err := os.WriteFile(certPath, cb, 0o644); err != nil {
		return "", "", nil, err
	}
	if err := os.WriteFile(keyPath, kbPem, 0o600); err != nil {
		return "", "", nil, err
	}
	return certPath, keyPath, cert, nil
}
