// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog_test

import (
	"testing"

	"github.com/varwof/pkcs7"

	"github.com/varwof/register/catalog"
)

func signCatalog(t *testing.T, f *fixtures, raw []byte) []byte {
	t.Helper()
	key := fixtureKey(t, f.corpus.Publishers["payments-ops"].Seed)
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, raw, f.certs["payments-ops"], key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestAcceptRejectsRollbackSkipForkAndProducerChange(t *testing.T) {
	f := newFixtures(t)
	policy := f.policy["standard"]
	roots := f.rootsFor("ca")
	raw1 := f.corpus.Catalogs["gen1"]
	raw2 := f.corpus.Catalogs["gen2"]

	state, res1, err := (catalog.RegistryState{}).AcceptSigned(raw1, signCatalog(t, f, raw1), roots, policy)
	if err != nil {
		t.Fatalf("accept gen1: %v", err)
	}
	if state.Generation != 1 || len(state.History) != 1 {
		t.Fatalf("state after gen1: %+v", state)
	}
	state, res2, err := state.AcceptSigned(raw2, signCatalog(t, f, raw2), roots, policy)
	if err != nil {
		t.Fatalf("accept gen2: %v", err)
	}
	if state.Generation != 2 || len(state.History) != 2 {
		t.Fatalf("state after gen2: %+v", state)
	}

	gen1, err := catalog.ParseCatalog(raw1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Accept(*gen1, res1); catalog.CodeOf(err) != catalog.CodeRollback {
		t.Fatalf("rollback: got %v", err)
	}

	gen2, err := catalog.ParseCatalog(raw2)
	if err != nil {
		t.Fatal(err)
	}
	// A result for gen2 cannot be replayed against a mutated artifact: the
	// result's catalogue digest must bind exactly.
	fork := *gen2
	fork.IssuedAt = "2026-10-22T00:00:00Z"
	if _, err := state.Accept(fork, res2); catalog.CodeOf(err) != catalog.CodeStateUnverified {
		t.Fatalf("fork: got %v", err)
	}

	changedProducer := *gen2
	changedProducer.Producer = "principal:other-publisher"
	if _, err := state.Accept(changedProducer, res2); catalog.CodeOf(err) != catalog.CodeIdentityMismatch {
		t.Fatalf("producer change: got %v", err)
	}

	if _, err := state.Accept(*gen2, res2); err != nil {
		t.Fatalf("idempotent replay rejected: %v", err)
	}
}
