// Decision Record — the evidence step of CLC.
//
// A DecisionRecord freezes the inputs of a decision together with the
// decision the language produced, so that a holder of nothing but the
// record can re-run the same language revision and reproduce the verdict.
// It adds no semantics: it serializes what AuthorizeSet already computed,
// hashes it, and stamps it with the language revision.

package semantics

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// RecordLang is the language identifier carried by every Decision Record.
const RecordLang = "clc-v1"

// DigestAlgSHA256 names the only digest algorithm this revision emits.
const DigestAlgSHA256 = "sha-256"

// Digest is a hash over a canonical byte string.  Its JSON form is
// {"alg": "...", "value": "<base64>"} — a CDDL bstr carried through JSON.
type Digest struct {
	Alg   string `json:"alg"`
	Value []byte `json:"value"`
}

// Equal reports whether two digests name the same algorithm and bytes.
func (d Digest) Equal(o Digest) bool {
	return d.Alg == o.Alg && bytes.Equal(d.Value, o.Value)
}

// RecordInputs is the frozen input of a decision: the grant set and the
// operation(s) it was evaluated against.  The field names are the record's
// public schema, not an internal detail.
type RecordInputs struct {
	Grants     []Grant     `json:"grants"`
	Operations []Operation `json:"operations"`
	// Context is the freshness input the decision was made under (RATS §10).
	// Omitted records predate it and keep the same digest: a nil context adds
	// no bytes.
	Context *DecisionContext `json:"context,omitempty"`
	// Sources is the authorization chain the decision rested on (EP-AEG §2).
	// Nil on records that predate it, so their digests are unchanged.
	Sources *SourceChain `json:"sources,omitempty"`
	// RequirementDigest identifies the relying party's evidence requirement
	// (CLC-REQUIREMENT-v1) that was applied.  The digest, not the object: the
	// bar belongs to the relying party's configuration, and a record only has
	// to say *which* revision it used (AEC §10).
	RequirementDigest *Digest `json:"requirement_digest,omitempty"`
}

// RecordOptions are the optional inputs a decision may be recorded with.  Both
// are part of the hashed inputs, so a record identifies exactly what it was
// decided from rather than "the same grant set, some other time, from some
// other authority".
type RecordOptions struct {
	Context *DecisionContext
	Sources *SourceChain
	// Requirement is the relying party's evidence requirement.  It is
	// validated and reduced to its profile digest, which becomes part of the
	// hashed inputs.  A presenter must not be able to supply or weaken it; this
	// API takes it from the caller's configuration, never from the inputs.
	Requirement *Requirement
}

// RecordConstraints carries the §8.4 residual-obligation channel of the
// decision.  This step records only what the core already computes:
// recognized-but-unevaluated constraints, in the decision's deterministic
// order.  External constraint evaluations are a later step.
type RecordConstraints struct {
	Unresolved []string `json:"unresolved,omitempty"`
}

// DecisionRecord is a self-contained, independently re-computable decision.
//
// Re-computation rules (the properties that make this evidence rather than
// a log line):
//
//  1. any holder of Inputs can re-run the same Ver and must obtain the same
//     Verdict / Reason / Constraints.Unresolved;
//  2. equal Inputs produce an equal InputDigest, so two implementations can
//     agree on "same decision input" without exchanging bytes;
//  3. a non-empty Constraints.Unresolved must accompany the
//     allow_unresolved verdict and never allow — Verify enforces this by
//     re-deriving the verdict rather than by trusting the field.
type DecisionRecord struct {
	Ver         string            `json:"ver"`  // CLC revision, e.g. CLCRevision
	Lang        string            `json:"lang"` // language identifier, RecordLang
	Inputs      RecordInputs      `json:"inputs"`
	InputDigest Digest            `json:"input_digest"`
	Constraints RecordConstraints `json:"constraints"`
	Verdict     string            `json:"verdict"`
	Reason      string            `json:"reason,omitempty"`
}

var (
	// ErrRecordOperationCount means the record does not carry exactly one
	// operation; this revision's verdict is singular, so the record must be.
	ErrRecordOperationCount = errors.New("record_operation_count")
	// ErrRecordDigestMismatch means Inputs no longer hash to InputDigest.
	ErrRecordDigestMismatch = errors.New("record_input_digest_mismatch")
	// ErrRecordVerdictMismatch means re-running the language over Inputs did
	// not reproduce the recorded Verdict / Reason / Unresolved.
	ErrRecordVerdictMismatch = errors.New("record_verdict_mismatch")
	// ErrRecordRevision means the record claims a language revision this
	// build cannot re-run, so the record cannot be checked (fail closed).
	ErrRecordRevision = errors.New("record_unsupported_revision")
)

// DigestOf returns the SHA-256 of v's canonical (JCS, RFC 8785) JSON encoding.
//
// The digest is the language's own handle, not a CAID: it is reproducible
// across any implementation that follows RFC 8785, so two holders can agree on
// "same decision input" by comparing digests.
func DigestOf(v any) (Digest, error) {
	b, err := CanonicalJSON(v)
	if err != nil {
		return Digest{}, err
	}
	sum := sha256.Sum256(b)
	return Digest{Alg: DigestAlgSHA256, Value: sum[:]}, nil
}

// Record runs a decision and freezes the inputs and the outcome together.
//
// The semantics are exactly AuthorizeSet's: Verdict, Reason and Unresolved
// are copied from its result unchanged, never recomputed or reworded here.
// Inputs are round-tripped through their canonical encoding so the record
// owns an independent, immutable copy of what was decided.
func Record(grants []Grant, op Operation) (DecisionRecord, error) {
	return RecordWith(grants, op, RecordOptions{})
}

// RecordWithContext records a decision together with the freshness context it
// was made under.  The context becomes part of the hashed inputs, so
// re-appraising the record means re-appraising the same instant, nonce or
// epoch — not "some time later, same verdict".
func RecordWithContext(grants []Grant, op Operation, ctx DecisionContext) (DecisionRecord, error) {
	return RecordWith(grants, op, RecordOptions{Context: &ctx})
}

// RecordWith records a decision with an optional freshness context and
// authorization source chain.  Both are validated before anything is written:
// a chain whose claimed relations its own bytes do not back is refused, not
// recorded.
func RecordWith(grants []Grant, op Operation, opts RecordOptions) (DecisionRecord, error) {
	if opts.Context != nil {
		if err := opts.Context.Validate(); err != nil {
			return DecisionRecord{}, err
		}
	}
	if opts.Sources != nil {
		if err := opts.Sources.Validate(); err != nil {
			return DecisionRecord{}, err
		}
	}
	var requirementDigest *Digest
	if opts.Requirement != nil {
		d, err := opts.Requirement.Digest()
		if err != nil {
			return DecisionRecord{}, err
		}
		requirementDigest = &d
	}
	return record(grants, op, opts, requirementDigest)
}

func record(grants []Grant, op Operation, opts RecordOptions, requirementDigest *Digest) (DecisionRecord, error) {
	if grants == nil {
		// Normalize before encoding: a nil slice would encode as null and
		// then hash differently from the empty list it decodes back to, so
		// the record would fail its own Verify.
		grants = []Grant{}
	}
	inputs := RecordInputs{
		Grants:            grants,
		Operations:        []Operation{op},
		Context:           opts.Context,
		Sources:           opts.Sources,
		RequirementDigest: requirementDigest,
	}
	canonical, err := CanonicalJSON(inputs)
	if err != nil {
		return DecisionRecord{}, err
	}
	frozen := RecordInputs{}
	if err := json.Unmarshal(canonical, &frozen); err != nil {
		return DecisionRecord{}, err
	}
	if frozen.Grants == nil {
		frozen.Grants = []Grant{}
	}

	rec := DecisionRecord{
		Ver:         CLCRevision,
		Lang:        RecordLang,
		Inputs:      frozen,
		InputDigest: DigestOfCanonical(canonical),
	}
	decision := AuthorizeSet(frozen.Grants, frozen.Operations[0])
	rec.Verdict = decision.Verdict
	rec.Reason = decision.Reason
	rec.Constraints.Unresolved = append([]string(nil), decision.Unresolved...)
	return rec, nil
}

// DigestOfCanonical hashes bytes already known to be canonical, so Record
// does not encode the inputs twice.
func DigestOfCanonical(canonical []byte) Digest {
	sum := sha256.Sum256(canonical)
	return Digest{Alg: DigestAlgSHA256, Value: sum[:]}
}

// CanonicalBytes returns the record's own canonical (JCS) encoding — the
// stable handle a later step signs, or compares between implementations.
func (r DecisionRecord) CanonicalBytes() ([]byte, error) {
	return CanonicalJSON(r)
}

// Recompute re-runs the language over the record's frozen inputs and
// returns the decision they produce.  It needs nothing outside the record.
func (r DecisionRecord) Recompute() (Decision, error) {
	if len(r.Inputs.Operations) != 1 {
		return Decision{}, fmt.Errorf("%w: %d operations", ErrRecordOperationCount, len(r.Inputs.Operations))
	}
	if !RevisionCompatible(r.Ver) {
		return Decision{}, fmt.Errorf("%w: %s", ErrRecordRevision, r.Ver)
	}
	return AuthorizeSet(r.Inputs.Grants, r.Inputs.Operations[0]), nil
}

// Verify checks a record a holder did not produce: the digest must match the
// frozen inputs, and re-running the language must reproduce the verdict,
// reason and residual obligations byte for byte.  Any failure is a hard
// error — a record that cannot be reproduced is not evidence.
// VerifyAsOf verifies the record and additionally requires its decision context
// to still be fresh at now (RATS §10).  A record that verifies but is stale is
// not evidence of a current decision: a historical re-performance must be
// labeled historical and must not be reused as a current execution decision
// (AEB §5.7).
func (r DecisionRecord) VerifyAsOf(now time.Time) error {
	if err := r.Verify(); err != nil {
		return err
	}
	if r.Inputs.Context == nil {
		return ErrContextMissing
	}
	return r.Inputs.Context.Fresh(now)
}

func (r DecisionRecord) Verify() error {
	recomputed, err := r.Recompute()
	if err != nil {
		return err
	}
	want, err := DigestOf(r.Inputs)
	if err != nil {
		return err
	}
	if !want.Equal(r.InputDigest) {
		return fmt.Errorf("%w: recorded %s/%x, recomputed %s/%x",
			ErrRecordDigestMismatch, r.InputDigest.Alg, r.InputDigest.Value, want.Alg, want.Value)
	}
	if recomputed.Verdict != r.Verdict || recomputed.Reason != r.Reason {
		return fmt.Errorf("%w: recorded %q/%q, recomputed %q/%q",
			ErrRecordVerdictMismatch, r.Verdict, r.Reason, recomputed.Verdict, recomputed.Reason)
	}
	if len(recomputed.Unresolved) != len(r.Constraints.Unresolved) {
		return fmt.Errorf("%w: recorded unresolved %v, recomputed %v",
			ErrRecordVerdictMismatch, r.Constraints.Unresolved, recomputed.Unresolved)
	}
	for i := range recomputed.Unresolved {
		if recomputed.Unresolved[i] != r.Constraints.Unresolved[i] {
			return fmt.Errorf("%w: recorded unresolved %v, recomputed %v",
				ErrRecordVerdictMismatch, r.Constraints.Unresolved, recomputed.Unresolved)
		}
	}
	return nil
}
