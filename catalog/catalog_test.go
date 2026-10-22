// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog_test

import (
	"encoding/json"
	"testing"

	"github.com/varwof/pkcs7"

	"github.com/varwof/register/catalog"
)

// TestSignatureRoundTrip proves the CLI's split: the detached signature is over
// the exact catalog bytes, and the recovered certificate still has to pass
// Verify's chain, AIC and authority checks.
func TestSignatureRoundTrip(t *testing.T) {
	f := newFixtures(t)
	cat, err := catalog.ParseCatalog(f.corpus.Catalogs["gen1"])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	raw, err := catalog.CanonicalBytes(*cat)
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	key := fixtureKey(t, f.corpus.Publishers["payments-ops"].Seed)
	der, err := pkcs7.BuildSignedData(pkcs7.OIDData, raw, f.certs["payments-ops"], key, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signer, err := pkcs7.VerifyDetached(der, raw)
	if err != nil {
		t.Fatalf("verify detached: %v", err)
	}
	if signer == nil {
		t.Fatal("no signer")
	}
	if _, err := pkcs7.VerifyDetached(der, append(append([]byte{}, raw...), ' ')); err == nil {
		t.Fatal("a changed byte must break the detached signature")
	}

	res, err := catalog.VerifySigned(raw, der, f.rootsFor("ca"), f.policy["standard"], f.corpus.States["empty"])
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Verdict != catalog.VerdictAccept {
		t.Fatalf("verdict %q", res.Verdict)
	}
	if res.CatalogDigest != f.corpus.States["gen1"].Digest {
		t.Fatalf("catalog digest %s", res.CatalogDigest)
	}
}

// TestCanonicalBytesDeterministic: two spellings of the same object must produce
// the same signed form.
func TestCanonicalBytesDeterministic(t *testing.T) {
	f := newFixtures(t)
	raw := f.corpus.Catalogs["gen1"]
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reordered, err := json.MarshalIndent(generic, "", "\t")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	a, err := catalog.ParseCatalog(raw)
	if err != nil {
		t.Fatalf("parse a: %v", err)
	}
	b, err := catalog.ParseCatalog(reordered)
	if err != nil {
		t.Fatalf("parse b: %v", err)
	}
	ba, _ := catalog.CanonicalBytes(*a)
	bb, _ := catalog.CanonicalBytes(*b)
	if string(ba) != string(bb) {
		t.Fatalf("canonical forms differ:\n%s\n%s", ba, bb)
	}
	da, _ := a.Digest()
	db, _ := b.Digest()
	if da != db {
		t.Fatalf("digests differ: %s %s", da, db)
	}
}

// TestDeltaOrderIndependence builds two deltas with the same effect but the
// removal list written in opposite orders.  Both must reproduce the same target
// digest, and the result must be ordered by capability.
func TestDeltaOrderIndependence(t *testing.T) {
	f := newFixtures(t)

	var baseObject map[string]any
	if err := json.Unmarshal(f.corpus.Catalogs["gen1-orders"], &baseObject); err != nil {
		t.Fatalf("base: %v", err)
	}
	var gen1Object map[string]any
	if err := json.Unmarshal(f.corpus.Catalogs["gen1"], &gen1Object); err != nil {
		t.Fatalf("gen1: %v", err)
	}
	// gen1-orders carries transfer + orders; add refund so two removals exist.
	entries := baseObject["entries"].([]any)
	baseObject["entries"] = append(entries, gen1Object["entries"].([]any)[1])
	baseRaw, _ := json.Marshal(baseObject)
	base, err := catalog.ParseCatalog(baseRaw)
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	baseDigest, err := base.Digest()
	if err != nil {
		t.Fatalf("base digest: %v", err)
	}

	target := map[string]any{}
	for key, value := range baseObject {
		target[key] = value
	}
	target["generation"] = 2
	target["previous_digest"] = baseDigest
	target["entries"] = []any{entries[0]} // transfer only
	targetRaw, _ := json.Marshal(target)
	expected, err := catalog.ParseCatalog(targetRaw)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	targetDigest, err := expected.Digest()
	if err != nil {
		t.Fatalf("target digest: %v", err)
	}

	makeDelta := func(remove []string) catalog.Delta {
		return catalog.Delta{
			Version:          catalog.DeltaVersion,
			Domain:           base.Domain,
			CatalogID:        base.CatalogID,
			BaseGeneration:   1,
			TargetGeneration: 2,
			BaseDigest:       baseDigest,
			TargetDigest:     targetDigest,
			IssuedAt:         "2026-10-22T00:59:55Z",
			ValidUntil:       "2026-10-22T01:10:00Z",
			Producer:         base.Producer,
			Remove:           remove,
		}
	}
	refund, orders := base.Entries[1].Capability, base.Entries[2].Capability
	first, err := catalog.Apply(*base, makeDelta([]string{refund, orders}))
	if err != nil {
		t.Fatalf("apply first: %v", err)
	}
	second, err := catalog.Apply(*base, makeDelta([]string{orders, refund}))
	if err != nil {
		t.Fatalf("apply second: %v", err)
	}
	firstDigest, _ := first.Digest()
	secondDigest, _ := second.Digest()
	if firstDigest != targetDigest || secondDigest != targetDigest {
		t.Fatalf("applied digests %s / %s, want %s", firstDigest, secondDigest, targetDigest)
	}
	if len(first.Entries) != 1 || first.Entries[0].Capability != base.Entries[0].Capability {
		t.Fatalf("remaining entries: %+v", first.Entries)
	}
}

func TestDiscoveryNeverCarriesAVerdict(t *testing.T) {
	for _, member := range []string{"verified", "authorized", "approved", "verdict"} {
		object := map[string]any{
			"@version":       catalog.DiscoveryVersion,
			"provider":       "spiffe://example.org/provider/payments",
			"catalog_id":     "example.org/payments/catalog",
			"catalog_digest": "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			"generation":     1,
			"issued_at":      "2026-10-22T00:59:55Z",
			"valid_until":    "2026-10-22T01:10:00Z",
			member:           true,
		}
		raw, _ := json.Marshal(object)
		if _, err := catalog.ParseDiscovery(raw); catalog.CodeOf(err) != catalog.CodeDiscoveryVerdict {
			t.Fatalf("%s: got %v", member, err)
		}
	}
}

func TestPolicyIsClosed(t *testing.T) {
	raw := []byte(`{"domain":"example.org/payments","catalog_id":"example.org/payments/catalog",` +
		`"schemes":{},"observed_at":"2026-10-22T01:00:00Z","authorized":true}`)
	dir := t.TempDir()
	path := dir + "/policy.json"
	if err := catalog.WriteFile(path, raw, false); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := catalog.LoadPolicy(path); err == nil {
		t.Fatal("policy with an extra member must be refused")
	}
}

func TestAcceptAdvancesWithoutRollback(t *testing.T) {
	f := newFixtures(t)
	policy := f.policy["standard"]
	roots := f.rootsFor("ca")
	raw1 := f.corpus.Catalogs["gen1"]
	raw2 := f.corpus.Catalogs["gen2"]
	state, _, err := (catalog.RegistryState{}).AcceptSigned(raw1, signCatalog(t, f, raw1), roots, policy)
	if err != nil {
		t.Fatalf("accept gen1: %v", err)
	}
	if state.Generation != 1 || len(state.History) != 1 {
		t.Fatalf("state after gen1: %+v", state)
	}
	state, _, err = state.AcceptSigned(raw2, signCatalog(t, f, raw2), roots, policy)
	if err != nil {
		t.Fatalf("accept gen2: %v", err)
	}
	if state.Generation != 2 || len(state.History) != 2 {
		t.Fatalf("state after gen2: %+v", state)
	}
	if state.History[0].Generation != 1 || state.History[1].Generation != 2 {
		t.Fatalf("history is not ordered: %+v", state.History)
	}
}

func mustDelta(t *testing.T, raw json.RawMessage) *catalog.Delta {
	t.Helper()
	d, err := catalog.ParseDelta(raw)
	if err != nil {
		t.Fatalf("delta: %v", err)
	}
	return d
}
