// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func dg(s string) Digest {
	sum := sha256.Sum256([]byte(s))
	return Digest{Alg: DigestAlgSHA256, Value: sum[:]}
}

// realisticChain models the AIC material as it actually nests: the AIC
// certificate's own extension carries the delegation authorization, so the AIC
// node's bytes name the delegation's digest (a byte-backed edge), and the
// delegation in turn stands on the principal's certificate.
func realisticChain() SourceChain {
	principal := dg("principal-cert-der")
	da := dg("delegation-authorization")
	aic := dg("aic-cert-der")

	return SourceChain{
		Sources: []SourceRef{
			{Kind: "principal-cert", ID: "people-user01:1", Issuer: "People CA", Digest: principal},
			{Kind: "delegation", ID: "da:v2:nonce-1", Issuer: "people-user01", Digest: da, References: []Digest{principal}},
			{Kind: "aic-x509", ID: "serial:7f3a", Issuer: "People CA", Digest: aic, References: []Digest{da}},
		},
		Links: []SourceLink{{From: aic, To: da}, {From: da, To: principal}},
	}
}

func TestSourceChainValidate(t *testing.T) {
	good := realisticChain()
	if err := good.Validate(); err != nil {
		t.Fatalf("realistic chain: %v", err)
	}
	if _, err := good.Digest(); err != nil {
		t.Fatalf("Digest: %v", err)
	}

	a, b, c := dg("a"), dg("b"), dg("c")

	cases := []struct {
		name  string
		chain SourceChain
		want  error
	}{
		{"empty", SourceChain{}, ErrSourceChainEmpty},
		{"missing kind", SourceChain{Sources: []SourceRef{{ID: "x", Digest: a}}}, ErrSourceShape},
		{"missing id", SourceChain{Sources: []SourceRef{{Kind: "k", Digest: a}}}, ErrSourceShape},
		{"unusable digest", SourceChain{Sources: []SourceRef{{Kind: "k", ID: "x"}}}, ErrSourceShape},
		{"duplicate digest", SourceChain{Sources: []SourceRef{{Kind: "k", ID: "1", Digest: a}, {Kind: "k", ID: "2", Digest: a}}}, ErrSourceDuplicate},
		{"dangling link", SourceChain{
			Sources: []SourceRef{{Kind: "k", ID: "1", Digest: a}},
			Links:   []SourceLink{{From: a, To: b}},
		}, ErrSourceDanglingLink},
		{"unbacked edge", SourceChain{
			Sources: []SourceRef{{Kind: "k", ID: "1", Digest: a}, {Kind: "k", ID: "2", Digest: b}},
			Links:   []SourceLink{{From: a, To: b}}, // a names nothing
		}, ErrSourceEdgeUnbacked},
		{"cycle", SourceChain{
			Sources: []SourceRef{
				{Kind: "k", ID: "1", Digest: a, References: []Digest{b}},
				{Kind: "k", ID: "2", Digest: b, References: []Digest{c}},
				{Kind: "k", ID: "3", Digest: c, References: []Digest{a}},
			},
			Links: []SourceLink{{From: a, To: b}, {From: b, To: c}, {From: c, To: a}},
		}, ErrSourceChainCycle},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.chain.Validate(); !errors.Is(err, tc.want) {
				t.Fatalf("Validate = %v, want %v", err, tc.want)
			}
		})
	}
}

// The chain's identity covers the node identities and the links, not the extra
// material a holder happens to disclose, so two parties with different
// disclosures agree on which chain they are discussing (EP-AEG §2.3).
func TestSourceChainIdentityIsDisclosureIndependent(t *testing.T) {
	a := realisticChain()
	b := realisticChain()
	b.Sources[1].References = append(b.Sources[1].References, dg("an extra receipt nobody asked about"))

	da, err := a.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if !da.Equal(db) {
		t.Error("extra disclosed material changed the chain identity")
	}

	// A different link set is a different chain.
	c := realisticChain()
	c.Links = c.Links[:1]
	dc, err := c.Digest()
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if da.Equal(dc) {
		t.Error("a different link set produced the same identity")
	}
}

func TestSourceChainStandingOn(t *testing.T) {
	chain := realisticChain()
	path, err := chain.StandingOn(chain.Sources[2].Digest)
	if err != nil {
		t.Fatalf("StandingOn: %v", err)
	}
	want := []string{"aic-x509", "delegation", "principal-cert"}
	if len(path) != len(want) {
		t.Fatalf("path = %d nodes, want %d", len(path), len(want))
	}
	for i, kind := range want {
		if path[i].Kind != kind {
			t.Fatalf("path[%d] = %q, want %q", i, path[i].Kind, kind)
		}
	}

	// The authoritative root stands on nothing.
	root, err := chain.StandingOn(path[len(path)-1].Digest)
	if err != nil {
		t.Fatalf("StandingOn(root): %v", err)
	}
	if len(root) != 1 {
		t.Errorf("root path = %d nodes, want 1", len(root))
	}

	if _, err := chain.StandingOn(dg("not-in-chain")); !errors.Is(err, ErrSourceDanglingLink) {
		t.Errorf("unknown source: got %v, want ErrSourceDanglingLink", err)
	}

	// A branching graph has no single path.
	branched := realisticChain()
	other := dg("another delegation")
	// The AIC's bytes name one delegation; a chain that claims two has no
	// single answer to "what does this stand on".
	branched.Sources = append(branched.Sources, SourceRef{Kind: "delegation", ID: "da:v1:old", Digest: other})
	branched.Sources[2].References = append(branched.Sources[2].References, other)
	branched.Links = append(branched.Links, SourceLink{From: branched.Sources[2].Digest, To: other})
	if err := branched.Validate(); err != nil {
		t.Fatalf("branched chain should still validate as a graph: %v", err)
	}
	if _, err := branched.StandingOn(branched.Sources[2].Digest); !errors.Is(err, ErrSourceChainBranch) {
		t.Errorf("branching: got %v, want ErrSourceChainBranch", err)
	}
}

// A record binds the chain: the sources are part of the hashed inputs, and an
// unbacked chain is refused before anything is recorded.
func TestRecordBindsSources(t *testing.T) {
	grant := Grant{ID: "std/database-v1:query:SELECT"}
	op := Operation{ID: "std/database-v1:query:SELECT"}
	chain := realisticChain()

	plain, err := Record([]Grant{grant}, op)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	withSources, err := RecordWith([]Grant{grant}, op, RecordOptions{Sources: &chain})
	if err != nil {
		t.Fatalf("RecordWith: %v", err)
	}
	if err := withSources.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if plain.InputDigest.Equal(withSources.InputDigest) {
		t.Error("sources must change the input digest")
	}
	if withSources.Inputs.Sources == nil || len(withSources.Inputs.Sources.Sources) != 3 {
		t.Fatalf("sources lost: %+v", withSources.Inputs.Sources)
	}

	// Tampering with a source digest breaks the record digest.
	withSources.Inputs.Sources.Sources[0].ID = "rewritten"
	if err := withSources.Verify(); !errors.Is(err, ErrRecordDigestMismatch) {
		t.Errorf("rewritten source: got %v, want ErrRecordDigestMismatch", err)
	}

	// An unbacked chain is not recorded at all.
	bad := realisticChain()
	bad.Sources[2].References = nil // the AIC no longer names the delegation
	if _, err := RecordWith([]Grant{grant}, op, RecordOptions{Sources: &bad}); !errors.Is(err, ErrSourceEdgeUnbacked) {
		t.Errorf("unbacked chain: got %v, want ErrSourceEdgeUnbacked", err)
	}
}

// Sources travel through the envelope, and the statement's subject binding
// still covers them (they are inside the hashed inputs).
func TestSourcesThroughEnvelope(t *testing.T) {
	chain := realisticChain()
	rec, err := RecordWith(
		[]Grant{{ID: "std/database-v1:query:SELECT"}},
		Operation{ID: "std/database-v1:query:SELECT"},
		RecordOptions{Sources: &chain},
	)
	if err != nil {
		t.Fatalf("RecordWith: %v", err)
	}
	env, err := NewEnvelope(rec)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if err := env.Check(); err != nil {
		t.Fatalf("Check: %v", err)
	}
	back, err := env.DecisionRecord()
	if err != nil {
		t.Fatalf("DecisionRecord: %v", err)
	}
	if back.Inputs.Sources == nil || len(back.Inputs.Sources.Sources) != 3 {
		t.Fatalf("sources lost in the envelope: %+v", back.Inputs.Sources)
	}
	// Re-targeting the envelope to another chain's subject is still refused.
	st, _ := env.Statement()
	other := realisticChain()
	other.Sources[0].Digest = dg("another principal")
	st.Subject[0].Digest["sha256"] = "00"
	payload, err := CanonicalJSON(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tampered := Envelope{Payload: payload, PayloadType: PayloadTypeInToto}
	if err := tampered.Check(); !errors.Is(err, ErrEnvelopeSubjectMismatch) {
		t.Errorf("re-targeted subject: got %v, want ErrEnvelopeSubjectMismatch", err)
	}
}
