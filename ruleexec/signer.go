// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"crypto/x509"

	"github.com/varwof/register/internal/rulesigner"
	pki "github.com/varwof/types"
)

// GenSignerCert generates a self-signed rule-signer certificate and key.
//
// This is a compatibility re-export.  The implementation lives in
// internal/rulesigner; the wrapper exists because moving an *exported* symbol
// into internal/ silently breaks every downstream module — Go forbids importing
// internal/ from outside this module, so consumers such as the gateway module's
// end-to-end fixtures (http/ruleplugins_test.go, e2e_real_test.go,
// e2e_matrix_test.go, gateway_rules_test.go) stopped compiling.
//
// Callers that need the AIC-carrying variants (so that RuleWithinSignerGrant can
// pass) should use the internal helper from inside this module.
func GenSignerCert(dir string) (certPath, keyPath string, cert *x509.Certificate, err error) {
	return rulesigner.GenSignerCert(dir)
}

// GenSignerCertWithCapabilities generates a signer certificate that carries an
// AIC extension whose grant covers caps.
//
// Rule *publication* requires this: the loader enforces RuleWithinSignerGrant, so
// a rule signed by a certificate without an AIC extension (the plain
// GenSignerCert above) is refused with "signer certificate has no AIC extension".
// Downstream modules — e.g. the gateway module's end-to-end fixtures — need this
// exported variant to build signers that can actually publish rules.
func GenSignerCertWithCapabilities(dir string, caps []pki.Capability) (certPath, keyPath string, cert *x509.Certificate, err error) {
	return rulesigner.GenSignerCertWithCapabilities(dir, caps)
}

// GenSignerCertWithGrant is GenSignerCertWithCapabilities plus constraints.
func GenSignerCertWithGrant(dir string, caps, constraints []pki.Capability) (certPath, keyPath string, cert *x509.Certificate, err error) {
	return rulesigner.GenSignerCertWithGrant(dir, caps, constraints)
}
