// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Evidence envelopes — carrying a Decision Record as a portable attestation.
//
// The record's own fields are CLC's, but the container is not: evidence
// consumers already speak DSSE envelopes and in-toto statements (and SCITT
// statements are the same shape with a transparency receipt attached).  Rather
// than invent a fourth container, a CLC decision record is carried as the
// *predicate* of an in-toto Statement inside a DSSE envelope:
//
//	DSSE envelope { payloadType, payload, signatures[] }
//	   payload = in-toto Statement {
//	       _type:         https://in-toto.io/Statement/v1
//	       subject:       [{name, digest{alg: hex}}]   <- the action it is about
//	       predicateType: https://varwof.com/clc/v1/decision-record
//	       predicate:     the DecisionRecord (ver / lang / inputs / digest / verdict)
//	   }
//
// Two rules come straight from the referenced specifications:
//
//   - DSSE signs PAE(payloadType, payload), not the payload alone, so a payload
//     cannot be reinterpreted under a different type ("PAE" = pre-authentication
//     encoding, DSSE v1.0.2).  A KEYID is an unauthenticated hint and MUST NOT be
//     used for security decisions.
//   - in-toto subjects are matched *purely by digest*, so an envelope whose
//     statement does not carry the decision's own action/input digests is
//     re-targetable and is refused (ErrEnvelopeSubjectMismatch).

package semantics

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

const (
	// PayloadTypeInToto is the DSSE payload type for an in-toto Statement.
	PayloadTypeInToto = "application/vnd.in-toto+json"
	// StatementTypeInToto is the in-toto Statement v1 schema type.
	StatementTypeInToto = "https://in-toto.io/Statement/v1"
	// PredicateTypeCLCDecision is this profile's predicate type.
	PredicateTypeCLCDecision = "https://varwof.com/clc/v1/decision-record"

	// subjectNameAction names the subject entry holding the action digest.
	subjectNameAction = "action"
	// subjectNameInputs names the subject entry holding the decision input digest.
	subjectNameInputs = "clc-inputs"
)

var (
	// ErrEnvelopeShape means the envelope or its statement is not the shape this
	// profile defines (missing members, wrong statement type, unparseable body).
	ErrEnvelopeShape = errors.New("envelope_shape")
	// ErrEnvelopePayloadType means the DSSE payload type is not the in-toto one.
	ErrEnvelopePayloadType = errors.New("envelope_payload_type")
	// ErrEnvelopeSubjectMismatch means the statement's subject digests do not
	// match the decision the predicate describes: the envelope has been
	// re-targeted and must not be consumed.
	ErrEnvelopeSubjectMismatch = errors.New("envelope_subject_mismatch")
	// ErrEnvelopeSignature means no signature verified (or verification failed).
	ErrEnvelopeSignature = errors.New("envelope_signature")
)

// Signature is one DSSE signature entry.  KeyID is an unauthenticated hint.
type Signature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   []byte `json:"sig"`
}

// Envelope is a DSSE v1.0.2 JSON envelope.  All three members MUST be present
// even when empty, so Signatures is never nil once NewEnvelope has run.
type Envelope struct {
	Payload     []byte      `json:"payload"`
	PayloadType string      `json:"payloadType"`
	Signatures  []Signature `json:"signatures"`
}

// Subject is one in-toto subject entry: a name and a digest keyed by algorithm
// in lowercase without separators (in-toto convention: "sha256").
type Subject struct {
	Name   string            `json:"name,omitempty"`
	Digest map[string]string `json:"digest"`
}

// Statement is an in-toto Statement v1 whose predicate is a CLC decision record.
type Statement struct {
	Type          string         `json:"_type"`
	Subject       []Subject      `json:"subject"`
	PredicateType string         `json:"predicateType"`
	Predicate     DecisionRecord `json:"predicate"`
}

// PAE returns the DSSE v1 pre-authentication encoding:
//
//	PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
//
// It is exported because every consumer must compute it identically; a signer
// and a verifier that disagree here silently fail to interoperate.
func PAE(payloadType string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1")
	writeLengthPrefixed(&b, []byte(payloadType))
	writeLengthPrefixed(&b, payload)
	return b.Bytes()
}

func writeLengthPrefixed(b *bytes.Buffer, v []byte) {
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(v)))
	b.WriteByte(' ')
	b.Write(v)
}

// inTotoAlg maps a CLC digest algorithm tag to the in-toto digest map key.
func inTotoAlg(alg string) (string, error) {
	switch alg {
	case DigestAlgSHA256:
		return "sha256", nil
	case "sha-384":
		return "sha384", nil
	case "sha-512":
		return "sha512", nil
	}
	return "", fmt.Errorf("%w: unsupported digest algorithm %q", ErrEnvelopeShape, alg)
}

// NewStatement builds the in-toto statement for a decision record.  The subjects
// are the action (the operation the decision is about) and the decision's own
// input digest, so both are covered by the statement and by any signature over
// it.
func NewStatement(rec DecisionRecord) (Statement, error) {
	if len(rec.Inputs.Operations) != 1 {
		return Statement{}, fmt.Errorf("%w: %d operations", ErrEnvelopeShape, len(rec.Inputs.Operations))
	}
	if rec.InputDigest.Alg == "" || len(rec.InputDigest.Value) == 0 {
		return Statement{}, fmt.Errorf("%w: record carries no input digest", ErrEnvelopeShape)
	}
	alg, err := inTotoAlg(rec.InputDigest.Alg)
	if err != nil {
		return Statement{}, err
	}
	actionBytes, err := CanonicalJSON(rec.Inputs.Operations)
	if err != nil {
		return Statement{}, err
	}
	actionDigest := sha256Hex(actionBytes)

	return Statement{
		Type:          StatementTypeInToto,
		PredicateType: PredicateTypeCLCDecision,
		Subject: []Subject{
			{Name: subjectNameAction, Digest: map[string]string{alg: actionDigest}},
			{Name: subjectNameInputs, Digest: map[string]string{alg: hex.EncodeToString(rec.InputDigest.Value)}},
		},
		Predicate: rec,
	}, nil
}

// NewEnvelope wraps a decision record in an unsigned DSSE envelope.
func NewEnvelope(rec DecisionRecord) (Envelope, error) {
	st, err := NewStatement(rec)
	if err != nil {
		return Envelope{}, err
	}
	payload, err := CanonicalJSON(st)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Payload:     payload,
		PayloadType: PayloadTypeInToto,
		Signatures:  []Signature{},
	}, nil
}

// Sign appends a signature over PAE(payloadType, payload).  The signing
// primitive is supplied by the caller: DSSE deliberately leaves the signature
// format to the out-of-band agreement, so this package does not pick one.
func (e *Envelope) Sign(keyID string, sign func(pae []byte) ([]byte, error)) error {
	if sign == nil {
		return fmt.Errorf("%w: nil signer", ErrEnvelopeShape)
	}
	pae := PAE(e.PayloadType, e.Payload)
	sig, err := sign(pae)
	if err != nil {
		return err
	}
	e.Signatures = append(e.Signatures, Signature{KeyID: keyID, Sig: sig})
	return nil
}

// Statement decodes the envelope's payload as an in-toto statement.
func (e Envelope) Statement() (Statement, error) {
	if e.PayloadType != PayloadTypeInToto {
		return Statement{}, fmt.Errorf("%w: %q", ErrEnvelopePayloadType, e.PayloadType)
	}
	var st Statement
	if len(e.Payload) == 0 {
		return Statement{}, fmt.Errorf("%w: empty payload", ErrEnvelopeShape)
	}
	if err := json.Unmarshal(e.Payload, &st); err != nil {
		return Statement{}, fmt.Errorf("%w: %v", ErrEnvelopeShape, err)
	}
	return st, nil
}

// DecisionRecord returns the decision record carried as the predicate.
func (e Envelope) DecisionRecord() (DecisionRecord, error) {
	st, err := e.Statement()
	if err != nil {
		return DecisionRecord{}, err
	}
	return st.Predicate, nil
}

// Check verifies the envelope's internal consistency without any signature:
// payload type, statement shape, subject binding to the decision, and the
// record's own digest/recomputation.
func (e Envelope) Check() error {
	st, err := e.Statement()
	if err != nil {
		return err
	}
	if st.Type != StatementTypeInToto {
		return fmt.Errorf("%w: statement type %q", ErrEnvelopeShape, st.Type)
	}
	if st.PredicateType != PredicateTypeCLCDecision {
		return fmt.Errorf("%w: predicate type %q", ErrEnvelopeShape, st.PredicateType)
	}
	if err := st.Predicate.Verify(); err != nil {
		return err
	}
	want, err := NewStatement(st.Predicate)
	if err != nil {
		return err
	}
	for _, w := range want.Subject {
		if err := matchSubject(st.Subject, w); err != nil {
			return err
		}
	}
	return nil
}

// matchSubject requires the statement to carry the expected subject entry with
// the same digest value.  Matching is by name and digest; the algorithm key must
// be identical, because a digest compared across algorithm names would be
// comparing different things.
func matchSubject(got []Subject, want Subject) error {
	for _, s := range got {
		if s.Name != want.Name {
			continue
		}
		for alg, value := range want.Digest {
			if s.Digest[alg] != value {
				return fmt.Errorf("%w: subject %q digest mismatch", ErrEnvelopeSubjectMismatch, want.Name)
			}
			return nil
		}
	}
	return fmt.Errorf("%w: subject %q missing", ErrEnvelopeSubjectMismatch, want.Name)
}

// VerifyRecord checks the envelope and then requires at least one signature to
// verify.  verify is the caller's signature primitive; it receives the KEYID
// hint (which MUST NOT be trusted on its own) and the PAE bytes.
func (e Envelope) VerifyRecord(verify func(keyID string, pae, sig []byte) error) error {
	if err := e.Check(); err != nil {
		return err
	}
	if len(e.Signatures) == 0 {
		return fmt.Errorf("%w: no signatures", ErrEnvelopeSignature)
	}
	if verify == nil {
		return fmt.Errorf("%w: nil verifier", ErrEnvelopeSignature)
	}
	pae := PAE(e.PayloadType, e.Payload)
	var firstErr error
	for _, sig := range e.Signatures {
		if len(sig.Sig) == 0 {
			if firstErr == nil {
				firstErr = fmt.Errorf("%w: empty signature", ErrEnvelopeSignature)
			}
			continue
		}
		if err := verify(sig.KeyID, pae, sig.Sig); err == nil {
			return nil
		} else if firstErr == nil {
			firstErr = fmt.Errorf("%w: %v", ErrEnvelopeSignature, err)
		}
	}
	return firstErr
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
