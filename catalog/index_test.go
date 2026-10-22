// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog_test

import (
	"fmt"
	"testing"

	"github.com/varwof/register/catalog"
)

func TestIndexLookupAndShard(t *testing.T) {
	c := catalog.Catalog{Entries: []catalog.Entry{
		{Capability: "a:one"}, {Capability: "b:two"}, {Capability: "a:three"},
	}}
	idx := catalog.BuildIndex(c)
	if e, ok := idx.Lookup(c, "b:two"); !ok || e.Capability != "b:two" {
		t.Fatalf("lookup b: %+v %v", e, ok)
	}
	if len(idx.Shard("a:one")) != 2 {
		t.Fatalf("shard a = %v", idx.Shard("a:one"))
	}
	if _, ok := idx.Lookup(c, "missing"); ok {
		t.Fatal("missing capability found")
	}
}

func BenchmarkBuildIndex10k(b *testing.B) {
	c := scaleCatalog(10_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = catalog.BuildIndex(c)
	}
}

func BenchmarkBuildIndex100k(b *testing.B) {
	c := scaleCatalog(100_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = catalog.BuildIndex(c)
	}
}

func BenchmarkShardedLookup(b *testing.B) {
	c := scaleCatalog(100_000)
	idx := catalog.BuildIndex(c)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = idx.Lookup(c, fmt.Sprintf("std/scale-v1:op%06d", i%100_000))
	}
}

func scaleCatalog(n int) catalog.Catalog {
	entries := make([]catalog.Entry, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, catalog.Entry{
			Capability: fmt.Sprintf("std/scale-v1:op%06d", i),
			Provider:   "spiffe://example.org/provider/scale",
			Scheme:     "std/scale-v1",
		})
	}
	return catalog.Catalog{Entries: entries}
}
