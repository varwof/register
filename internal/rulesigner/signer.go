// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package rulesigner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"

	pki "github.com/varwof/types"
)

// GenSignerCert creates a self-signed signer certificate and key for
// rule signing (PKCS#7). Returns PEM file paths and the parsed cert.
// The certificate carries no AIC extension (convenience default).
func GenSignerCert(dir string) (certPath, keyPath string, cert *x509.Certificate, err error) {
	return GenSignerCertWithCapabilities(dir, nil)
}

// GenSignerCertWithCapabilities creates a signer certificate that carries an
// AIC extension declaring the given capabilities.  ruleexec requires a rule's
// capability to be covered by the signer's AIC grant, so tests (and real
// deployments) use this variant to publish rules under a bounded authority.
func GenSignerCertWithCapabilities(dir string, caps []pki.Capability) (certPath, keyPath string, cert *x509.Certificate, err error) {
	return GenSignerCertWithGrant(dir, caps, nil)
}

// GenSignerCertWithGrant also declares the signer's authorization constraints,
// which ruleexec requires for any constraint a rule declares.
func GenSignerCertWithGrant(dir string, caps, constraints []pki.Capability) (certPath, keyPath string, cert *x509.Certificate, err error) {
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
	if len(caps) > 0 || len(constraints) > 0 {
		aic := pki.AIC{
			Version:                  1,
			AgentId:                  "agent:rule-publisher",
			PrincipalUid:             pki.PrincipalUid{Realm: "corp.com", Identifier: "rule-publisher", KeyHash: make([]byte, 32)},
			Capabilities:             caps,
			AuthorizationConstraints: constraints,
			DelegationAuthorization: pki.DelegationAuthorization{
				Reason:             pki.Reason{ReasonCode: "rule-publish", Description: "publish signed rules"},
				RequestedLifetime:  3600,
				Timestamp:          now,
				Nonce:              make([]byte, 32),
				SignatureAlgorithm: pki.SigAlgoToOID(x509.ECDSAWithSHA256),
				SignatureValue:     []byte{0x01},
			},
		}
		der, err := asn1.Marshal(aic)
		if err != nil {
			return "", "", nil, err
		}
		tmpl.ExtraExtensions = []pkix.Extension{{Id: pki.OIDAIC, Value: der}}
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
