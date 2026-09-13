// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func utc(t time.Time) time.Time { return t.UTC() }

func TestDecisionContextValidate(t *testing.T) {
	now := time.Now().UTC()
	good := Digest{Alg: DigestAlgSHA256, Value: make([]byte, 32)}

	cases := []struct {
		name string
		ctx  DecisionContext
		want error
	}{
		{"zero", DecisionContext{}, ErrContextMissing},
		{"clock only", DecisionContext{At: now}, nil},
		{"clock with bound", DecisionContext{At: now, MaxAgeSec: 60}, nil},
		{"nonce only", DecisionContext{Nonce: "n-1"}, nil},
		{"epoch zero is present", DecisionContext{EpochID: EpochIDOf(0)}, nil},
		{"all mechanisms", DecisionContext{At: now, MaxAgeSec: 60, Nonce: "n", EpochID: EpochIDOf(7), SnapshotDigest: &good}, nil},
		{"bound without instant", DecisionContext{MaxAgeSec: 60}, ErrContextShape},
		{"negative bound", DecisionContext{At: now, MaxAgeSec: -1}, ErrContextShape},
		{"local-offset instant", DecisionContext{At: time.Now().In(time.FixedZone("CST", 8*3600))}, ErrContextNotUTC},
		{"incomplete snapshot digest", DecisionContext{At: now, SnapshotDigest: &Digest{Alg: DigestAlgSHA256}}, ErrContextShape},
		{"oversized nonce", DecisionContext{Nonce: strings.Repeat("n", maxContextNonceBytes+1)}, ErrContextShape},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ctx.Validate()
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Validate: %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Validate = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDecisionContextFresh(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name string
		ctx  DecisionContext
		want error
	}{
		{"inside bound", DecisionContext{At: now.Add(-30 * time.Second), MaxAgeSec: 60}, nil},
		{"no bound", DecisionContext{At: now.Add(-24 * time.Hour)}, nil},
		{"stale", DecisionContext{At: now.Add(-2 * time.Minute), MaxAgeSec: 60}, ErrContextStale},
		{"future", DecisionContext{At: now.Add(time.Minute)}, ErrContextFuture},
		{"nonce only has no clock", DecisionContext{Nonce: "n"}, ErrContextNoClock},
		{"epoch only has no clock", DecisionContext{EpochID: EpochIDOf(3)}, ErrContextNoClock},
		{"absent context", DecisionContext{}, ErrContextMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ctx.Fresh(now)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Fresh: %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Fresh = %v, want %v", err, tc.want)
			}
		})
	}
}

// The context is part of the hashed inputs, so a record identifies exactly the
// freshness input it was decided under, and touching it breaks the digest.
func TestRecordBindsDecisionContext(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	grant := Grant{ID: "std/database-v1:query:SELECT", Constraints: []string{windowObligation}}
	op := Operation{ID: "std/database-v1:query:SELECT"}
	ctx := DecisionContext{At: now, MaxAgeSec: 60, Nonce: "nonce-1", SnapshotDigest: &Digest{Alg: DigestAlgSHA256, Value: make([]byte, 32)}}

	plain, err := Record([]Grant{grant}, op)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	withCtx, err := RecordWithContext([]Grant{grant}, op, ctx)
	if err != nil {
		t.Fatalf("RecordWithContext: %v", err)
	}

	if err := withCtx.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if plain.InputDigest.Equal(withCtx.InputDigest) {
		t.Error("a context must change the input digest")
	}
	if err := plain.VerifyAsOf(now); !errors.Is(err, ErrContextMissing) {
		t.Errorf("VerifyAsOf without a context: got %v, want ErrContextMissing", err)
	}
	if err := withCtx.VerifyAsOf(now); err != nil {
		t.Errorf("VerifyAsOf at the decision instant: %v", err)
	}
	if err := withCtx.VerifyAsOf(now.Add(2 * time.Minute)); !errors.Is(err, ErrContextStale) {
		t.Errorf("VerifyAsOf later: got %v, want ErrContextStale", err)
	}

	// Same input twice -> same digest (determinism).
	again, err := RecordWithContext([]Grant{grant}, op, ctx)
	if err != nil {
		t.Fatalf("RecordWithContext: %v", err)
	}
	if !again.InputDigest.Equal(withCtx.InputDigest) {
		t.Error("identical context produced a different digest")
	}

	// A context that is not validated cannot be recorded at all.
	if _, err := RecordWithContext([]Grant{grant}, op, DecisionContext{}); !errors.Is(err, ErrContextMissing) {
		t.Errorf("empty context: got %v, want ErrContextMissing", err)
	}
}

func TestRecordContextTamperIsCaught(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rec, err := RecordWithContext(
		[]Grant{{ID: "std/database-v1:query:SELECT"}},
		Operation{ID: "std/database-v1:query:SELECT"},
		DecisionContext{At: now, MaxAgeSec: 60},
	)
	if err != nil {
		t.Fatalf("RecordWithContext: %v", err)
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	rec.Inputs.Context.At = rec.Inputs.Context.At.Add(time.Hour)
	if err := rec.Verify(); !errors.Is(err, ErrRecordDigestMismatch) {
		t.Errorf("rewritten context: got %v, want ErrRecordDigestMismatch", err)
	}
}

// Records without a context keep the exact step-1 shape: no new JSON member, so
// their digests are unchanged.
func TestRecordWithoutContextKeepsStepOneShape(t *testing.T) {
	rec, err := Record([]Grant{{ID: "std/database-v1:query:SELECT"}}, Operation{ID: "std/database-v1:query:SELECT"})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	b, err := json.Marshal(rec.Inputs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "context") {
		t.Errorf("context-free inputs grew a member: %s", b)
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// An epoch id of zero survives the record round trip as "present".
func TestEpochZeroRoundTrips(t *testing.T) {
	ctx := DecisionContext{EpochID: EpochIDOf(0)}
	b, err := json.Marshal(ctx)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back DecisionContext
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.EpochID == nil || *back.EpochID != 0 {
		t.Fatalf("epoch id lost in round trip: %s", b)
	}
	if err := back.Validate(); err != nil {
		t.Errorf("round-tripped context invalid: %v", err)
	}
	_ = utc // keep the helper referenced for future UTC-formatting assertions
}
