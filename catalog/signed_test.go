// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package catalog_test

import (
	"encoding/json"
	"testing"

	"github.com/varwof/pkcs7"

	"github.com/varwof/register/catalog"
)

// TestVerifySignedDeltaRequiresProducerSignature pins the delta consumer path:
// the exact delta bytes are signed, the signer must be the delta producer, and
// the producer must continue the base producer.
func TestVerifySignedDeltaRequiresProducerSignature(t *testing.T) {
	f := newFixtures(t)
	base, err := catalog.ParseCatalog(f.corpus.Catalogs["gen1"])
	if err != nil {
		t.Fatal(err)
	}
	raw := f.corpus.Deltas["d-apply"]
	key := fixtureKey(t, f.corpus.Publishers["payments-ops"].Seed)
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, raw, f.certs["payments-ops"], key, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := f.rootsFor("ca")
	policy := f.policy["standard"]
	res, next, err := catalog.VerifySignedDelta(raw, sig, *base, roots, policy)
	if err != nil {
		t.Fatalf("verify signed delta: %v", err)
	}
	if res.Verdict != catalog.VerdictAccept || next.Generation != 2 {
		t.Fatalf("result %+v next generation %d", res, next.Generation)
	}
	d, err := catalog.ParseDelta(raw)
	if err != nil {
		t.Fatal(err)
	}
	if digest, _ := next.Digest(); digest != d.TargetDigest {
		t.Fatalf("next digest %s", digest)
	}
	baseDigest, _ := base.Digest()
	accepted := catalog.RegistryState{
		Domain:     base.Domain,
		CatalogID:  base.CatalogID,
		Generation: base.Generation,
		Digest:     baseDigest,
	}
	if _, _, err := catalog.VerifySignedDeltaWithState(raw, sig, *base, roots, policy, accepted); err != nil {
		t.Fatalf("accepted head state rejected: %v", err)
	}
	if _, _, err := catalog.VerifySignedDeltaWithState(raw, sig, *base, roots, policy, catalog.RegistryState{}); catalog.CodeOf(err) != catalog.CodeBootstrap {
		t.Fatalf("empty state: got %v", err)
	}

	if _, _, err := catalog.VerifySignedDelta(raw, nil, *base, roots, policy); catalog.CodeOf(err) != catalog.CodeSignatureInvalid {
		t.Fatalf("unsigned delta: got %v", err)
	}

	// A different producer's signature does not bind the delta producer.
	other := fixtureKey(t, f.corpus.Publishers["other-ops"].Seed)
	otherSig, err := pkcs7.BuildSignedData(pkcs7.OIDData, raw, f.certs["other-ops"], other, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := catalog.VerifySignedDelta(raw, otherSig, *base, roots, policy); catalog.CodeOf(err) != catalog.CodePublisherMismatch {
		t.Fatalf("wrong producer: got %v", err)
	}
}
func TestVerifySignedDeltaRechecksCompleteNextCatalog(t *testing.T) {
	f := newFixtures(t)
	base, err := catalog.ParseCatalog(f.corpus.Catalogs["gen1"])
	if err != nil {
		t.Fatal(err)
	}
	d, err := catalog.ParseDelta(f.corpus.Deltas["d-apply"])
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Replace) != 1 {
		t.Fatalf("fixture delta has %d replacements", len(d.Replace))
	}
	d.Replace[0].Status = nil

	next := catalog.Catalog{
		Version:        catalog.CatalogVersion,
		Domain:         d.Domain,
		CatalogID:      d.CatalogID,
		Generation:     d.TargetGeneration,
		IssuedAt:       d.IssuedAt,
		ValidUntil:     d.ValidUntil,
		PreviousDigest: d.BaseDigest,
		Producer:       d.Producer,
		Entries:        []catalog.Entry{d.Replace[0]},
	}
	digest, err := next.Digest()
	if err != nil {
		t.Fatal(err)
	}
	d.TargetDigest = digest
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	key := fixtureKey(t, f.corpus.Publishers["payments-ops"].Seed)
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, raw, f.certs["payments-ops"], key, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy := f.policy["standard"]
	policy.RequireStatus = true
	if _, _, err := catalog.VerifySignedDelta(raw, sig, *base, f.rootsFor("ca"), policy); catalog.CodeOf(err) != catalog.CodeStatusUnavailable {
		t.Fatalf("delta without required status: got %v", err)
	}
}

func TestVerifyLegacyEntryPointFailsClosed(t *testing.T) {
	res, err := catalog.Verify(catalog.Verification{})
	if catalog.CodeOf(err) != catalog.CodeSignatureMissing {
		t.Fatalf("Verify legacy entry point: code %q, want %q", catalog.CodeOf(err), catalog.CodeSignatureMissing)
	}
	if res.Verdict != catalog.VerdictReject {
		t.Fatalf("legacy Verify verdict = %q", res.Verdict)
	}
}

func TestAcceptRejectsUnsignedResult(t *testing.T) {
	f := newFixtures(t)
	gen1, err := catalog.ParseCatalog(f.corpus.Catalogs["gen1"])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (catalog.RegistryState{}).Accept(*gen1, catalog.Result{Verdict: catalog.VerdictAccept}); catalog.CodeOf(err) != catalog.CodeStateUnverified {
		t.Fatalf("unsigned result accepted: %v", err)
	}
}

func TestRequireStatusNeedsResolvedHealthyValue(t *testing.T) {
	f := newFixtures(t)
	raw := f.corpus.Catalogs["gen1"]
	sig := signCatalog(t, f, raw)
	policy := f.policy["strict-status"]
	if _, err := catalog.VerifySigned(raw, sig, f.rootsFor("ca"), policy, f.corpus.States["empty"]); err != nil {
		t.Fatalf("resolved status rejected: %v", err)
	}

	missing := policy
	missing.StatusValues = nil
	if _, err := catalog.VerifySigned(raw, sig, f.rootsFor("ca"), missing, f.corpus.States["empty"]); catalog.CodeOf(err) != catalog.CodeStatusUnavailable {
		t.Fatalf("missing status resolution: got %v", err)
	}

	unhealthy := policy
	unhealthy.StatusValues = map[string]string{"status:provider-payments": "unhealthy"}
	if _, err := catalog.VerifySigned(raw, sig, f.rootsFor("ca"), unhealthy, f.corpus.States["empty"]); catalog.CodeOf(err) != catalog.CodeStatusUnavailable {
		t.Fatalf("unhealthy status: got %v", err)
	}
}

func TestProviderBindingsBindToProducer(t *testing.T) {
	f := newFixtures(t)
	raw := f.corpus.Catalogs["gen1"]
	sig := signCatalog(t, f, raw)
	cat, err := catalog.ParseCatalog(raw)
	if err != nil {
		t.Fatal(err)
	}
	provider := cat.Entries[0].Provider
	policy := f.policy["standard"]
	policy.ProviderBindings = map[string]string{provider: cat.Producer}
	if _, err := catalog.VerifySigned(raw, sig, f.rootsFor("ca"), policy, f.corpus.States["empty"]); err != nil {
		t.Fatalf("bound provider rejected: %v", err)
	}
	policy.ProviderBindings = map[string]string{provider: "principal:other-publisher"}
	if _, err := catalog.VerifySigned(raw, sig, f.rootsFor("ca"), policy, f.corpus.States["empty"]); catalog.CodeOf(err) != catalog.CodeProviderMismatch {
		t.Fatalf("wrong provider binding: got %v", err)
	}
}

func TestVerifySignedBindsSignatureToBytes(t *testing.T) {
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
	sig, err := pkcs7.BuildSignedData(pkcs7.OIDData, raw, f.certs["payments-ops"], key, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	roots := f.rootsFor("ca")
	policy := f.policy["standard"]
	state := f.corpus.States["empty"]

	res, err := catalog.VerifySigned(raw, sig, roots, policy, state)
	if err != nil {
		t.Fatalf("verify signed: %v", err)
	}
	if res.Verdict != catalog.VerdictAccept {
		t.Fatalf("verdict %q", res.Verdict)
	}
	if res.CatalogDigest != f.corpus.States["gen1"].Digest {
		t.Fatalf("catalog digest %s", res.CatalogDigest)
	}

	// A changed byte breaks the signature even though the catalog still parses.
	if _, err := catalog.VerifySigned(append(append([]byte{}, raw...), ' '), sig, roots, policy, state); catalog.CodeOf(err) != catalog.CodeSignatureInvalid {
		t.Fatalf("tampered catalog: code %q, want %q", catalog.CodeOf(err), catalog.CodeSignatureInvalid)
	}

	// No signature means no signer to recover.
	if _, err := catalog.VerifySigned(raw, nil, roots, policy, state); catalog.CodeOf(err) != catalog.CodeSignatureMissing {
		t.Fatalf("missing signature: code %q, want %q", catalog.CodeOf(err), catalog.CodeSignatureMissing)
	}

	// The signature is checked before parsing: an unsigned malformed object is
	// refused at the signature step, and a correctly signed malformed object
	// then reaches shape validation.
	if _, err := catalog.VerifySigned([]byte("{}"), sig, roots, policy, state); catalog.CodeOf(err) != catalog.CodeSignatureInvalid {
		t.Fatalf("unsigned malformed artifact: code %q, want %q", catalog.CodeOf(err), catalog.CodeSignatureInvalid)
	}
	emptySig, err := pkcs7.BuildSignedData(pkcs7.OIDData, []byte("{}"), f.certs["payments-ops"], key, nil)
	if err != nil {
		t.Fatalf("sign empty object: %v", err)
	}
	if _, err := catalog.VerifySigned([]byte("{}"), emptySig, roots, policy, state); catalog.CodeOf(err) != catalog.CodeCatalogShape {
		t.Fatalf("signed malformed artifact: code %q, want %q", catalog.CodeOf(err), catalog.CodeCatalogShape)
	}
}

func TestStatusResolverOverridesPinnedValue(t *testing.T) {
	f := newFixtures(t)
	raw := f.corpus.Catalogs["gen1"]
	sig := signCatalog(t, f, raw)
	policy := f.policy["strict-status"]
	policy.StatusValues = nil
	policy.StatusResolver = func(string) (string, error) { return "unhealthy", nil }
	if _, err := catalog.VerifySigned(raw, sig, f.rootsFor("ca"), policy, f.corpus.States["empty"]); catalog.CodeOf(err) != catalog.CodeStatusUnavailable {
		t.Fatalf("unhealthy resolver: got %v", err)
	}
	policy.StatusResolver = func(string) (string, error) { return "healthy", nil }
	if _, err := catalog.VerifySigned(raw, sig, f.rootsFor("ca"), policy, f.corpus.States["empty"]); err != nil {
		t.Fatalf("healthy resolver: %v", err)
	}
}
