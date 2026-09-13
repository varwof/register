// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package semantics

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestPAEEncoding pins the DSSE pre-authentication encoding byte for byte: a
// signer and a verifier that disagree here silently fail to interoperate, so
// this is an interop vector, not an implementation detail.
func TestPAEEncoding(t *testing.T) {
	got := string(PAE(PayloadTypeInToto, []byte("hello")))
	want := "DSSEv1 28 application/vnd.in-toto+json 5 hello"
	if got != want {
		t.Fatalf("PAE = %q, want %q", got, want)
	}
	// Length prefixes make the encoding unambiguous: the concatenation of type
	// and body cannot be re-split.
	if bytes.Equal(PAE("ab", []byte("c")), PAE("a", []byte("bc"))) {
		t.Error("PAE is ambiguous across type/body boundaries")
	}
	if empty := PAE("", nil); string(empty) != "DSSEv1 0  0 " {
		t.Errorf("empty PAE = %q", empty)
	}
}

func testRecord(t *testing.T, opID string) DecisionRecord {
	t.Helper()
	rec, err := Record(
		[]Grant{{ID: opID, Constraints: []string{windowObligation}}},
		Operation{ID: opID},
	)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	return rec
}

func fakeSign(keyID string) func([]byte) ([]byte, error) {
	return func(pae []byte) ([]byte, error) {
		return append([]byte(keyID+":"), pae...), nil
	}
}

func fakeVerify(keyID string, pae, sig []byte) error {
	if !bytes.Equal(append([]byte(keyID+":"), pae...), sig) {
		return errors.New("signature does not match")
	}
	return nil
}

func TestEnvelopeRoundTrip(t *testing.T) {
	rec := testRecord(t, "std/database-v1:query:SELECT")
	env, err := NewEnvelope(rec)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if env.PayloadType != PayloadTypeInToto {
		t.Errorf("payload type = %q", env.PayloadType)
	}
	if env.Signatures == nil || len(env.Signatures) != 0 {
		t.Errorf("signatures must be present-and-empty, got %#v", env.Signatures)
	}
	if err := env.Check(); err != nil {
		t.Fatalf("Check: %v", err)
	}

	// The statement carries the action and the decision input as subjects.
	st, err := env.Statement()
	if err != nil {
		t.Fatalf("Statement: %v", err)
	}
	if st.Type != StatementTypeInToto || st.PredicateType != PredicateTypeCLCDecision {
		t.Fatalf("statement types = %q/%q", st.Type, st.PredicateType)
	}
	names := map[string]bool{}
	for _, s := range st.Subject {
		if len(s.Digest) == 0 {
			t.Fatalf("subject %q has no digest", s.Name)
		}
		names[s.Name] = true
	}
	if !names[subjectNameAction] || !names[subjectNameInputs] {
		t.Fatalf("subjects = %v, want action + clc-inputs", names)
	}

	// JSON round trip (the wire form) preserves the record.
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Envelope
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, err := back.DecisionRecord()
	if err != nil {
		t.Fatalf("DecisionRecord: %v", err)
	}
	if got.Verdict != rec.Verdict || got.Reason != rec.Reason || !got.InputDigest.Equal(rec.InputDigest) {
		t.Fatalf("record changed in the envelope: %+v vs %+v", got, rec)
	}
	if err := back.Check(); err != nil {
		t.Errorf("Check after round trip: %v", err)
	}

	// Determinism: the same record produces byte-identical payloads.
	again, err := NewEnvelope(rec)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if !bytes.Equal(env.Payload, again.Payload) {
		t.Error("envelope payload is not deterministic for the same record")
	}
}

func TestEnvelopeSignAndVerify(t *testing.T) {
	rec := testRecord(t, "std/database-v1:query:SELECT")
	env, err := NewEnvelope(rec)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if err := env.Sign("key-1", fakeSign("key-1")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := env.VerifyRecord(fakeVerify); err != nil {
		t.Fatalf("VerifyRecord: %v", err)
	}

	// A tampered signature fails when it is the only one.
	single := env
	single.Signatures = append([]Signature(nil), env.Signatures...)
	single.Signatures[0].Sig = append([]byte(nil), env.Signatures[0].Sig...)
	single.Signatures[0].Sig[len(single.Signatures[0].Sig)-1] ^= 0xff
	if err := single.VerifyRecord(fakeVerify); !errors.Is(err, ErrEnvelopeSignature) {
		t.Errorf("tampered signature: got %v, want ErrEnvelopeSignature", err)
	}

	// DSSE multi-signature semantics: separate signatures are equivalent to
	// separate envelopes, so one valid signature is enough ...
	if err := env.Sign("key-2", fakeSign("key-2")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	partial := env
	partial.Signatures = append([]Signature(nil), env.Signatures...)
	partial.Signatures[0] = single.Signatures[0] // key-1 broken, key-2 intact
	if err := partial.VerifyRecord(fakeVerify); err != nil {
		t.Errorf("one intact signature must satisfy an unpinned verifier: %v", err)
	}

	// ... and a deployment that pins a key enforces that in its verifier: the
	// KEYID is only an unauthenticated hint, so the callback decides.
	pinKey1 := func(keyID string, pae, sig []byte) error {
		if keyID != "key-1" {
			return errors.New("unpinned key")
		}
		return fakeVerify(keyID, pae, sig)
	}
	if err := partial.VerifyRecord(pinKey1); !errors.Is(err, ErrEnvelopeSignature) {
		t.Errorf("key-pinning verifier must reject a broken pinned signature: got %v", err)
	}

	// Any payload change breaks Check (it is bound to the record) ...
	payloadTampered, _ := NewEnvelope(rec)
	payloadTampered.Payload = append([]byte(nil), payloadTampered.Payload...)
	payloadTampered.Payload[10] ^= 0x01
	if err := payloadTampered.Check(); err == nil {
		t.Error("a mutated payload must not pass Check")
	}

	// ... and an unsigned envelope never verifies.
	unsigned, _ := NewEnvelope(rec)
	if err := unsigned.VerifyRecord(fakeVerify); !errors.Is(err, ErrEnvelopeSignature) {
		t.Errorf("unsigned: got %v, want ErrEnvelopeSignature", err)
	}
}

// A statement whose subjects describe a different decision is re-targeted
// evidence: it must be refused even though every signature over it is valid.
func TestEnvelopeSubjectBinding(t *testing.T) {
	a := testRecord(t, "std/database-v1:query:SELECT")
	b := testRecord(t, "std/database-v1:query:INSERT")

	stA, err := NewStatement(a)
	if err != nil {
		t.Fatalf("NewStatement: %v", err)
	}
	stB, err := NewStatement(b)
	if err != nil {
		t.Fatalf("NewStatement: %v", err)
	}
	reTargeted := stA
	reTargeted.Subject = stB.Subject
	payload, err := CanonicalJSON(reTargeted)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	env := Envelope{Payload: payload, PayloadType: PayloadTypeInToto, Signatures: []Signature{}}
	if err := env.Sign("key-1", fakeSign("key-1")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := env.Check(); !errors.Is(err, ErrEnvelopeSubjectMismatch) {
		t.Fatalf("re-targeted envelope: got %v, want ErrEnvelopeSubjectMismatch", err)
	}
	// The signature is fine; the binding is not.  Consumption must stop here.
	if err := env.VerifyRecord(fakeVerify); !errors.Is(err, ErrEnvelopeSubjectMismatch) {
		t.Errorf("VerifyRecord: got %v, want ErrEnvelopeSubjectMismatch", err)
	}
}

func TestEnvelopeRejectsWrongContainer(t *testing.T) {
	rec := testRecord(t, "std/database-v1:query:SELECT")

	// A bare DecisionRecord is valid JSON but not a statement.
	bare, err := CanonicalJSON(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	bareEnv := Envelope{Payload: bare, PayloadType: PayloadTypeInToto, Signatures: []Signature{}}
	if _, err := bareEnv.Statement(); err != nil {
		t.Fatalf("Statement should parse structurally: %v", err)
	}
	if err := bareEnv.Check(); !errors.Is(err, ErrEnvelopeShape) {
		t.Errorf("bare record payload: got %v, want ErrEnvelopeShape", err)
	}

	// A non-in-toto payload type is refused before any parsing.
	wrongType := Envelope{Payload: bare, PayloadType: "application/json", Signatures: []Signature{}}
	if _, err := wrongType.DecisionRecord(); !errors.Is(err, ErrEnvelopePayloadType) {
		t.Errorf("wrong payload type: got %v, want ErrEnvelopePayloadType", err)
	}

	empty := Envelope{PayloadType: PayloadTypeInToto}
	if _, err := empty.DecisionRecord(); !errors.Is(err, ErrEnvelopeShape) {
		t.Errorf("empty payload: got %v, want ErrEnvelopeShape", err)
	}

	// A record without an input digest cannot be bound as a subject.
	if _, err := NewStatement(DecisionRecord{Ver: CLCRevision}); !errors.Is(err, ErrEnvelopeShape) {
		t.Errorf("record without digest: got %v, want ErrEnvelopeShape", err)
	}
}

// Records written before the envelope (and before the decision context) must
// still parse and verify, so the container change is additive.
func TestLegacyRecordJSONStillParses(t *testing.T) {
	rec, err := Record([]Grant{{ID: "std/database-v1:query:SELECT"}}, Operation{ID: "std/database-v1:query:SELECT"})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	wire, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(wire), "\"context\"") {
		t.Errorf("context-free record grew a member: %s", wire)
	}
	var back DecisionRecord
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := back.Verify(); err != nil {
		t.Fatalf("legacy record no longer verifies: %v", err)
	}

	// And such a record still becomes a valid envelope.
	env, err := NewEnvelope(back)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if err := env.Check(); err != nil {
		t.Errorf("Check: %v", err)
	}

	// A context-bearing record keeps working through the envelope too.
	ctx := DecisionContext{At: time.Now().UTC().Truncate(time.Second), MaxAgeSec: 60}
	withCtx, err := RecordWithContext([]Grant{{ID: "std/database-v1:query:SELECT"}}, Operation{ID: "std/database-v1:query:SELECT"}, ctx)
	if err != nil {
		t.Fatalf("RecordWithContext: %v", err)
	}
	ctxEnv, err := NewEnvelope(withCtx)
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	got, err := ctxEnv.DecisionRecord()
	if err != nil {
		t.Fatalf("DecisionRecord: %v", err)
	}
	if got.Inputs.Context == nil {
		t.Fatal("context lost in the envelope")
	}
	if err := got.VerifyAsOf(time.Now().UTC()); err != nil {
		t.Errorf("VerifyAsOf through the envelope: %v", err)
	}
}
