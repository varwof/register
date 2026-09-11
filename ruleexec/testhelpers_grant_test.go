// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"crypto/x509"
	"testing"

	pki "github.com/varwof/types"

	"github.com/varwof/register/internal/rulesigner"
)

// genSignerForRules creates a signer certificate whose AIC grant covers the
// database-v1 capabilities used by the rule fixtures (wildcard, no bound), so
// that publication is authorized.
func genSignerForRules(t *testing.T, dir string) (certPath, keyPath string, cert *x509.Certificate, err error) {
	t.Helper()
	certPath, keyPath, cert, err = rulesigner.GenSignerCertWithGrant(dir,
		[]pki.Capability{{SchemeId: "std/database-v1", CapabilityId: "query:*"}},
		[]pki.Capability{{SchemeId: "varwof/constraint-v1", CapabilityId: "allowed-cidr", Parameters: []byte(`["10.0.0.0/8"]`)}},
	)
	if err != nil {
		t.Fatalf("gen signer with grant: %v", err)
	}
	return certPath, keyPath, cert, nil
}
