// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog_test

import (
	"testing"
	"time"

	"github.com/varwof/register/catalog"
)

func TestTrustRotationOverlapAndRevocation(t *testing.T) {
	f := newFixtures(t)
	raw := f.corpus.Catalogs["gen1"]
	sig := signCatalog(t, f, raw)
	roots := f.rootsFor("ca")
	policy := f.policy["standard"]
	observed, err := time.Parse(time.RFC3339, policy.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	rotation := catalog.TrustRotation{
		Current:      roots,
		Next:         roots,
		OverlapUntil: observed.Add(time.Hour),
	}
	if got, err := rotation.RootsAt(observed); err != nil || len(got) != 2*len(roots) {
		t.Fatalf("overlap roots = %d, %v", len(got), err)
	}
	if got, err := rotation.RootsAt(observed.Add(2 * time.Hour)); err != nil || len(got) != len(roots) {
		t.Fatalf("post-overlap roots = %d, %v", len(got), err)
	}
	res, _, err := rotation.VerifySigned(raw, sig, policy, catalog.RegistryState{})
	if err != nil || res.Verdict != catalog.VerdictAccept {
		t.Fatalf("rotation verify: %v %+v", err, res)
	}
	rotation.RevokedKeys = map[string]bool{res.SignerKeyID: true}
	if _, _, err := rotation.VerifySigned(raw, sig, policy, catalog.RegistryState{}); catalog.CodeOf(err) != catalog.CodeKeyRevoked {
		t.Fatalf("revoked signer: %v", err)
	}
}
