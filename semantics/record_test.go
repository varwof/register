package semantics

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
)

// recordVector mirrors cmd/vectors-run's view of the corpus.  Only the
// fields this test needs are decoded.
type recordVector struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	CLCRevision string     `json:"clc_revision"`
	RawParams   string     `json:"raw_params,omitempty"`
	Grant       *Grant     `json:"grant"`
	Request     *Operation `json:"request"`
	Others      []Grant    `json:"others"`
	Multi       bool       `json:"multi,omitempty"`
	Expect      struct {
		Verdict    string   `json:"verdict"`
		Reason     string   `json:"reason,omitempty"`
		Unresolved []string `json:"unresolved,omitempty"`
	} `json:"expect"`
}

func vectorsPath() string {
	if p := os.Getenv("CLC_VECTORS"); p != "" {
		return p
	}
	return "../../capability/data/_vectors/clc-v1/vectors.json"
}

// canonicalReason mirrors cmd/vectors-run: the stable code is everything
// before the first ':'.
func canonicalReason(s string) string {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i]
	}
	return s
}

func joinSorted(v []string) string {
	out := append([]string(nil), v...)
	sort.Strings(out)
	return strings.Join(out, "\x00")
}

// TestRecordVectorsRecompute is the core acceptance property: for every
// corpus vector that carries a grant and an operation, Recording it and
// then re-running the language over rec.Inputs must reproduce the record,
// and the record must verify against its own digest.
func TestRecordVectorsRecompute(t *testing.T) {
	data, err := os.ReadFile(vectorsPath())
	if err != nil {
		t.Skipf("vector corpus unavailable (%v)", err)
	}
	var vectors []recordVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	recorded, decided := 0, 0
	for _, v := range vectors {
		if v.Request == nil || v.Kind == "syntax" || v.Kind == "intersect" {
			continue
		}

		grants := []Grant{}
		if v.Grant != nil {
			grants = append(grants, *v.Grant)
		}
		switch {
		case v.Multi:
			grants = append(grants, v.Others...)
		case v.Kind == "decide" && len(v.Others) > 0:
			// Combined vector: the corpus intersects first and only then
			// decides, so the record's grant set is the intersection.
			merged, err := Intersect(append(append([]Grant{}, grants...), v.Others...)...)
			if err != nil {
				continue // the intersection itself is the asserted denial
			}
			grants = []Grant{merged}
		}

		rec, err := Record(grants, *v.Request)
		if err != nil {
			t.Fatalf("%s: Record: %v", v.ID, err)
		}
		recorded++

		if rec.Ver != CLCRevision || rec.Lang != RecordLang {
			t.Errorf("%s: record stamped %s/%s, want %s/%s", v.ID, rec.Ver, rec.Lang, CLCRevision, RecordLang)
		}
		digest, err := DigestOf(rec.Inputs)
		if err != nil {
			t.Fatalf("%s: DigestOf: %v", v.ID, err)
		}
		if !digest.Equal(rec.InputDigest) {
			t.Errorf("%s: input digest not reproducible: recorded %x, recomputed %x", v.ID, rec.InputDigest.Value, digest.Value)
		}
		if err := rec.Verify(); err != nil {
			t.Errorf("%s: Verify: %v", v.ID, err)
		}

		recomputed, err := rec.Recompute()
		if err != nil {
			t.Fatalf("%s: Recompute: %v", v.ID, err)
		}
		if recomputed.Verdict != rec.Verdict || recomputed.Reason != rec.Reason {
			t.Errorf("%s: recompute %q/%q, recorded %q/%q", v.ID, recomputed.Verdict, recomputed.Reason, rec.Verdict, rec.Reason)
		}
		if strings.Join(recomputed.Unresolved, "\x00") != strings.Join(rec.Constraints.Unresolved, "\x00") {
			t.Errorf("%s: recompute unresolved %v, recorded %v", v.ID, recomputed.Unresolved, rec.Constraints.Unresolved)
		}

		// For decide vectors the record must also agree with the corpus
		// expectation — that is the Record == AuthorizeSet check.  Vectors
		// whose expectation is resolved at the input boundary (declared
		// revision, raw params) are not reachable through Record's grant /
		// operation inputs, so they are checked for reproducibility only.
		if v.Kind != "decide" || v.RawParams != "" || !RevisionCompatible(v.CLCRevision) {
			continue
		}
		decided++
		if rec.Verdict != v.Expect.Verdict {
			t.Errorf("%s: record verdict %q, corpus expects %q", v.ID, rec.Verdict, v.Expect.Verdict)
		}
		if got, want := canonicalReason(rec.Reason), canonicalReason(v.Expect.Reason); got != want {
			t.Errorf("%s: record reason %q, corpus expects %q", v.ID, got, want)
		}
		if v.Expect.Unresolved != nil {
			if got, want := joinSorted(rec.Constraints.Unresolved), joinSorted(v.Expect.Unresolved); got != want {
				t.Errorf("%s: record unresolved %q, corpus expects %q", v.ID, got, want)
			}
		}
	}

	if recorded < 80 {
		t.Fatalf("only %d vectors recorded, expected the corpus decide/entail set", recorded)
	}
	t.Logf("recomputed %d records (%d decide vectors asserted against the corpus)", recorded, decided)
}

// TestRecordTamperDetection: any mutation of the frozen inputs, the verdict
// or the digest must be caught.  Each case starts from a fresh record so a
// slice shared with an earlier case cannot leak one mutation into the next.
func TestRecordTamperDetection(t *testing.T) {
	fresh := func(t *testing.T) DecisionRecord {
		t.Helper()
		rec, err := Record(
			[]Grant{{ID: "std/database-v1:query:SELECT"}},
			Operation{ID: "std/database-v1:query:SELECT"},
		)
		if err != nil {
			t.Fatalf("Record: %v", err)
		}
		if rec.Verdict != VerdictAllow {
			t.Fatalf("baseline verdict = %q, want allow", rec.Verdict)
		}
		if err := rec.Verify(); err != nil {
			t.Fatalf("baseline Verify: %v", err)
		}
		return rec
	}

	// 1. An input mutation must change the recomputed digest.
	tampered := fresh(t)
	tampered.Inputs.Operations[0].ID = "std/database-v1:query:INSERT"
	mutatedDigest, err := DigestOf(tampered.Inputs)
	if err != nil {
		t.Fatalf("DigestOf: %v", err)
	}
	if mutatedDigest.Equal(tampered.InputDigest) {
		t.Error("input mutation did not change the digest")
	}
	if err := tampered.Verify(); !errors.Is(err, ErrRecordDigestMismatch) {
		t.Errorf("tampered inputs: got %v, want ErrRecordDigestMismatch", err)
	}

	// 2. A verdict rewrite must be caught by re-running the language.
	rewritten := fresh(t)
	rewritten.Verdict = VerdictDeny
	if err := rewritten.Verify(); !errors.Is(err, ErrRecordVerdictMismatch) {
		t.Errorf("rewritten verdict: got %v, want ErrRecordVerdictMismatch", err)
	}

	// 3. Injecting a residual obligation the language did not produce must
	//    be caught even though the verdict itself still matches.
	injected := fresh(t)
	injected.Constraints.Unresolved = []string{`varwof/constraint-v1:time:window:[{"start":"09:00","end":"18:00"}]`}
	if err := injected.Verify(); !errors.Is(err, ErrRecordVerdictMismatch) {
		t.Errorf("injected obligation: got %v, want ErrRecordVerdictMismatch", err)
	}

	// 4. A digest rewrite must be caught by hashing the inputs.
	digestTampered := fresh(t)
	digestTampered.InputDigest.Value = append([]byte(nil), digestTampered.InputDigest.Value...)
	digestTampered.InputDigest.Value[0] ^= 0xff
	if err := digestTampered.Verify(); !errors.Is(err, ErrRecordDigestMismatch) {
		t.Errorf("tampered digest: got %v, want ErrRecordDigestMismatch", err)
	}

	// 5. A claimed revision this build cannot re-run fails closed rather
	//    than being verified against the wrong semantics.
	future := fresh(t)
	future.Ver = "CLC-2.0"
	if err := future.Verify(); !errors.Is(err, ErrRecordRevision) {
		t.Errorf("future revision: got %v, want ErrRecordRevision", err)
	}

	// 6. A record with no operation cannot be re-run at all.
	empty := fresh(t)
	empty.Inputs.Operations = nil
	if err := empty.Verify(); !errors.Is(err, ErrRecordOperationCount) {
		t.Errorf("no operation: got %v, want ErrRecordOperationCount", err)
	}
}

// TestRecordRealPKIExample pins the one record taken from a real run of the
// whole chain (user certificate PA -> DA v2 -> AIC -> CLC): a recognized but
// unevaluated time:window constraint yields allow_unresolved plus a residual
// obligation, while the same operation under an unconstrained grant yields
// a plain allow.
func TestRecordRealPKIExample(t *testing.T) {
	const (
		grantID = "varwof/demo-mysql-v1:SELECT:*"
		window  = `varwof/constraint-v1:time:window:[{"start":"09:00","end":"18:00"}]`
	)

	constrained, err := Record(
		[]Grant{{ID: grantID, Constraints: []string{window}}},
		Operation{ID: grantID},
	)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if constrained.Verdict != VerdictAllowUR {
		t.Fatalf("constrained verdict = %q, want %q (reason %q)", constrained.Verdict, VerdictAllowUR, constrained.Reason)
	}
	if constrained.Reason != "" {
		t.Errorf("allow_unresolved must carry no reason code, got %q", constrained.Reason)
	}
	if got := constrained.Constraints.Unresolved; len(got) != 1 || got[0] != window {
		t.Fatalf("unresolved = %v, want exactly [%s]", got, window)
	}
	if err := constrained.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	unconstrained, err := Record([]Grant{{ID: grantID}}, Operation{ID: grantID})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if unconstrained.Verdict != VerdictAllow || len(unconstrained.Constraints.Unresolved) != 0 {
		t.Fatalf("unconstrained = %q/%v, want allow with no residual obligations", unconstrained.Verdict, unconstrained.Constraints.Unresolved)
	}
	if constrained.InputDigest.Equal(unconstrained.InputDigest) {
		t.Error("differing inputs produced the same digest")
	}
	if err := unconstrained.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestRecordNilGrants: an absent grant set must still produce a record that
// verifies against itself (nil and [] must not hash differently).
func TestRecordNilGrants(t *testing.T) {
	rec, err := Record(nil, Operation{ID: "std/database-v1:query:SELECT"})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if rec.Verdict != VerdictDeny {
		t.Fatalf("verdict = %q, want deny", rec.Verdict)
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	empty, err := Record([]Grant{}, Operation{ID: "std/database-v1:query:SELECT"})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if !empty.InputDigest.Equal(rec.InputDigest) {
		t.Error("nil and empty grant sets must hash identically")
	}
}

// TestRecordFrozenInputs: mutating the caller's grants after Record must not
// change the record, otherwise it is not evidence.
func TestRecordFrozenInputs(t *testing.T) {
	grant := Grant{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(10)}}
	op := Operation{ID: "std/database-v1:query:SELECT", Params: map[string]any{"limit": float64(5)}}
	rec, err := Record([]Grant{grant}, op)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if rec.Verdict != VerdictAllow {
		t.Fatalf("verdict = %q, want allow", rec.Verdict)
	}

	grant.Params["limit"] = float64(1)
	op.Params["limit"] = float64(99)
	if err := rec.Verify(); err != nil {
		t.Fatalf("caller mutation leaked into the record: %v", err)
	}
}
