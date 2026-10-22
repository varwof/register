// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/varwof/pkcs7"

	"github.com/varwof/register/catalog"
)

func TestDirectoryBundleDeltaAndSnapshotFallback(t *testing.T) {
	f := newFixtures(t)
	gen1, err := catalog.ParseCatalog(f.corpus.Catalogs["gen1"])
	if err != nil {
		t.Fatal(err)
	}
	gen2Raw := f.corpus.Catalogs["gen2"]
	gen2Sig := signCatalog(t, f, gen2Raw)
	deltaRaw := f.corpus.Deltas["d-apply"]
	key := fixtureKey(t, f.corpus.Publishers["payments-ops"].Seed)
	deltaSig, err := pkcs7.BuildSignedData(pkcs7.OIDData, deltaRaw, f.certs["payments-ops"], key, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := f.corpus.States["gen1"]
	bundle := catalog.DirectoryBundle{
		Snapshot: gen2Raw, SnapshotSignature: gen2Sig,
		Delta: deltaRaw, DeltaSignature: deltaSig,
	}
	res, next, usedDelta, err := bundle.Apply(*gen1, f.rootsFor("ca"), f.policy["standard"], state)
	if err != nil || res.Verdict != catalog.VerdictAccept || !usedDelta || next.Generation != 2 {
		t.Fatalf("delta apply: %v used=%v res=%+v", err, usedDelta, res)
	}

	// A delta that cannot be applied falls back to the signed full snapshot.
	fallback := bundle
	fallback.DeltaSignature = nil
	res, next, usedDelta, err = fallback.Apply(*gen1, f.rootsFor("ca"), f.policy["standard"], state)
	if err != nil || res.Verdict != catalog.VerdictAccept || usedDelta || next.Generation != 2 {
		t.Fatalf("snapshot fallback: %v used=%v res=%+v", err, usedDelta, res)
	}

	server := httptest.NewServer(bundle.Handler())
	defer server.Close()
	fetched, err := catalog.FetchDirectory(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("fetch directory: %v", err)
	}
	if string(fetched.Snapshot) != string(gen2Raw) || len(fetched.DeltaSignature) == 0 {
		t.Fatal("fetched bundle bytes drifted")
	}
}

func TestDirectoryCacheFreshAndStaleFallback(t *testing.T) {
	f := newFixtures(t)
	gen2Raw := f.corpus.Catalogs["gen2"]
	bundle := catalog.DirectoryBundle{Snapshot: gen2Raw, SnapshotSignature: signCatalog(t, f, gen2Raw)}
	server := httptest.NewServer(bundle.Handler())
	defer server.Close()
	cache := &catalog.DirectoryCache{TTL: time.Minute, MaxStale: time.Hour}
	now := time.Now().UTC()
	if _, hit, stale, err := cache.Fetch(context.Background(), server.Client(), server.URL, now); err != nil || hit || stale {
		t.Fatalf("first fetch: hit=%v stale=%v err=%v", hit, stale, err)
	}
	if _, hit, stale, err := cache.Fetch(context.Background(), server.Client(), server.URL, now.Add(time.Second)); err != nil || !hit || stale {
		t.Fatalf("fresh cache: hit=%v stale=%v err=%v", hit, stale, err)
	}
	server.Close()
	if _, hit, stale, err := cache.Fetch(context.Background(), server.Client(), server.URL, now.Add(2*time.Minute)); err != nil || !hit || !stale {
		t.Fatalf("stale fallback: hit=%v stale=%v err=%v", hit, stale, err)
	}
}
