// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog_test

import (
	"testing"

	"github.com/varwof/register/catalog"
)

func verifiedSource(t *testing.T, f *fixtures, name string, raw []byte) catalog.VerifiedSource {
	t.Helper()
	src, err := catalog.VerifySource(name, raw, signCatalog(t, f, raw), f.rootsFor("ca"), f.policy["standard"], f.corpus.States["empty"])
	if err != nil {
		t.Fatalf("verify source %s: %v", name, err)
	}
	return src
}

func TestComposeVerifiedHashesAndConflicts(t *testing.T) {
	f := newFixtures(t)
	raw := f.corpus.Catalogs["gen1"]
	first := verifiedSource(t, f, "dir-a", raw)
	second := verifiedSource(t, f, "dir-b", raw)
	composite, err := catalog.ComposeVerified([]catalog.VerifiedSource{first, second}, []string{"dir-a", "dir-b"})
	if err != nil {
		t.Fatalf("compose identical shards: %v", err)
	}
	if composite.Generation != 1 || len(composite.Entries) != 2 || len(composite.Sources) != 2 {
		t.Fatalf("composite = %+v", composite)
	}
	if _, ok := composite.Entry("std/payments-v1:transfer"); !ok {
		t.Fatal("transfer entry missing")
	}

	cat, err := catalog.ParseCatalog(raw)
	if err != nil {
		t.Fatal(err)
	}
	conflict := *cat
	conflict.Entries = append([]catalog.Entry(nil), cat.Entries...)
	conflict.Entries[0].Provider = "spiffe://example.org/provider/other"
	rawConflict, err := catalog.CanonicalBytes(conflict)
	if err != nil {
		t.Fatal(err)
	}
	third := verifiedSource(t, f, "dir-c", rawConflict)
	if _, err := catalog.ComposeVerified([]catalog.VerifiedSource{first, third}, nil); catalog.CodeOf(err) != catalog.CodeDirectoryConflict {
		t.Fatalf("conflicting shards: got %v", err)
	}
	if _, err := catalog.ComposeVerified([]catalog.VerifiedSource{first}, []string{"required-dir"}); catalog.CodeOf(err) != catalog.CodeShardMissing {
		t.Fatalf("missing required shard: got %v", err)
	}
}
