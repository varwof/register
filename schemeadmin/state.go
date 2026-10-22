// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import (
	"crypto/x509"
	"time"

	"github.com/varwof/pkcs7"
)

// Accept returns the registry state to persist after a successful confirmation.
// It is deliberately a pure state transition: the caller must pass the result
// of Confirm/ConfirmSigned, and this method re-checks that the result binds the
// same package and transition before advancing the head.  It never mutates the
// receiver.
func (s RegistryState) Accept(c Confirmation, res ConfirmationResult) (RegistryState, error) {
	if !res.signed {
		return s, fail(CodeStateUnverified, "state can only be advanced from a ConfirmSigned result")
	}
	if res.Verdict != VerdictAccept {
		return s, fail(CodeStateShape, "cannot persist a non-accept confirmation")
	}
	pkgDigest, err := PackageDigest(c.Package)
	if err != nil {
		return s, err
	}
	trDigest, err := TransitionDigest(c.Transition)
	if err != nil {
		return s, err
	}
	if res.PackageDigest != pkgDigest || res.TransitionDigest != trDigest {
		return s, fail(CodeStateShape, "confirmation result does not bind this package/transition")
	}
	if c.Package.Scheme != c.Transition.Scheme {
		return s, fail(CodePackageTransitionMismatch, "package and transition schemes differ")
	}
	if c.Transition.ToGeneration != c.Package.Generation {
		return s, fail(CodePackageTransitionMismatch, "transition to_generation %d, package generation %d", c.Transition.ToGeneration, c.Package.Generation)
	}

	if c.Transition.Action == ActionCreate {
		if s.Generation != 0 || len(s.History) != 0 || s.PackageDigest != "" {
			return s, fail(CodeStateNotEmpty, "create requires an empty namespace state")
		}
		if c.Transition.ToGeneration != 1 {
			return s, fail(CodeCreateShape, "create must be generation 1")
		}
	} else {
		if c.Transition.FromGeneration == nil {
			return s, fail(CodeTransitionShape, "transition requires from_generation")
		}
		if s.Generation != *c.Transition.FromGeneration {
			return s, fail(CodeStateGeneration, "state generation %d, transition from_generation %d", s.Generation, *c.Transition.FromGeneration)
		}
		if s.PackageDigest != c.Transition.FromDigest {
			return s, fail(CodeStateDigest, "state digest %s, transition from_digest %s", s.PackageDigest, c.Transition.FromDigest)
		}
		if c.Transition.ToGeneration != s.Generation+1 {
			return s, fail(CodeStateGeneration, "transition must advance exactly one generation")
		}
	}
	if d, ok := s.digestAt(c.Transition.ToGeneration); ok && d != res.PackageDigest {
		return s, fail(CodeGenerationFork, "generation %d already holds %s", c.Transition.ToGeneration, d)
	}

	next := s
	next.Scheme = c.Package.Scheme
	next.Revision = c.Package.Revision
	next.Generation = c.Transition.ToGeneration
	next.PackageDigest = res.PackageDigest
	next.History = append([]RegistryEntry(nil), s.History...)
	if len(next.History) == 0 || next.History[len(next.History)-1].Generation != next.Generation {
		next.History = append(next.History, RegistryEntry{Generation: next.Generation, PackageDigest: res.PackageDigest})
	}
	next.Revoked = append([]Revocation(nil), s.Revoked...)
	next.Approvals = append([]Approval(nil), s.Approvals...)

	if c.Transition.Action == ActionRevoke {
		if c.Transition.FromDigest == "" {
			return s, fail(CodeTransitionShape, "revoke requires from_digest")
		}
		if c.Transition.ReplacementDigest == c.Transition.FromDigest {
			return s, fail(CodeRevocationInvalid, "replacement_digest equals the revoked digest")
		}
		if _, err := time.Parse(time.RFC3339, c.Transition.RevocationEffectiveTime); err != nil {
			return s, fail(CodeRevocationInvalid, "revocation_effective_time is not RFC3339")
		}
		for _, r := range next.Revoked {
			if r.PackageDigest == c.Transition.FromDigest {
				return s, fail(CodeRevocationInvalid, "digest %s is already revoked", c.Transition.FromDigest)
			}
		}
		generation := c.Transition.ToGeneration
		if c.Transition.TombstoneGeneration != nil {
			generation = *c.Transition.TombstoneGeneration
		}
		if len(c.TransitionBytes) == 0 || len(c.TransitionSignature) == 0 {
			return s, fail(CodeRevocationInvalid, "revoke requires a signed tombstone transition")
		}
		now, err := policyTime(c.Policy)
		if err != nil {
			return s, err
		}
		record := Revocation{
			PackageDigest:     c.Transition.FromDigest,
			Generation:        generation,
			EffectiveTime:     c.Transition.RevocationEffectiveTime,
			Reason:            c.Transition.RevocationReason,
			ReplacementDigest: c.Transition.ReplacementDigest,
			Tombstone:         append([]byte(nil), c.TransitionBytes...),
			Signature:         append([]byte(nil), c.TransitionSignature...),
		}
		if err := verifyTombstone(record, c.Package.Scheme, c.Roots, now); err != nil {
			return s, err
		}
		if d, err := TransitionDigest(c.Transition); err != nil || res.TransitionDigest != d {
			return s, fail(CodeRevocationInvalid, "tombstone does not bind the confirmation transition")
		}
		next.Revoked = append(next.Revoked, record)
	}
	return next, nil
}

// AcceptSigned verifies a full SignedConfirmation and then advances state with
// the exact signed transition available for the tombstone record.
func (s RegistryState) AcceptSigned(sc SignedConfirmation) (RegistryState, ConfirmationResult, error) {
	res, err := ConfirmSigned(sc)
	if err != nil {
		return s, res, err
	}
	pkg, err := ParsePackage(sc.PackageBytes)
	if err != nil {
		return s, res, err
	}
	tr, err := ParseTransition(sc.TransitionBytes)
	if err != nil {
		return s, res, err
	}
	var publisher *x509.Certificate
	for _, sig := range sc.Signatures {
		cert, err := pkcs7.VerifyDetached(sig, sc.PackageBytes)
		if err == nil && cert != nil && KeyID(cert) == res.PublisherKeyID {
			publisher = cert
			break
		}
	}
	var transitionSig []byte
	if publisher != nil {
		transitionSig = transitionSignatureFor(publisher, sc.TransitionSignatures, sc.TransitionBytes)
	}
	next, err := s.Accept(Confirmation{
		Package:             pkg,
		Transition:          tr,
		Definition:          sc.Definition,
		Declaration:         sc.Declaration,
		TransitionBytes:     sc.TransitionBytes,
		TransitionSignature: transitionSig,
		Roots:               sc.Roots,
		State:               s,
		Policy:              sc.Policy,
	}, res)
	return next, res, err
}

// ParseState decodes a closed local registry state from exact bytes.
func ParseState(raw []byte) (RegistryState, error) {
	var s RegistryState
	if len(raw) > maxArtifactBytes {
		return s, fail(CodeStateShape, "state is %d bytes, limit is %d", len(raw), maxArtifactBytes)
	}
	if err := decodeClosed(raw, &s); err != nil {
		return s, fail(CodeStateShape, "state: %s", err)
	}
	return s, nil
}

// verifyRevocations authenticates every persisted tombstone.  A state file is a
// local input, so unsigned or tampered revocation records are not trusted even
// if they were once accepted.
func (s RegistryState) verifyRevocations(roots []*x509.Certificate, now time.Time) error {
	for i := range s.Revoked {
		if err := verifyTombstone(s.Revoked[i], s.Scheme, roots, now); err != nil {
			return err
		}
	}
	return nil
}

func verifyTombstone(r Revocation, scheme string, roots []*x509.Certificate, now time.Time) error {
	if len(r.Tombstone) == 0 || len(r.Signature) == 0 {
		return fail(CodeRevocationInvalid, "tombstone for %s is unsigned", r.PackageDigest)
	}
	cert, err := pkcs7.VerifyDetached(r.Signature, r.Tombstone)
	if err != nil {
		return fail(CodeRevocationInvalid, "tombstone signature: %s", err)
	}
	if _, err := verifyCertificate(cert, roots, now); err != nil {
		return fail(CodeRevocationInvalid, "tombstone signer: %s", err)
	}
	tr, err := ParseTransition(r.Tombstone)
	if err != nil {
		return fail(CodeRevocationInvalid, "tombstone transition: %s", err)
	}
	if tr.Action != ActionRevoke || tr.Scheme != scheme {
		return fail(CodeRevocationInvalid, "tombstone is not a revoke transition for %s", scheme)
	}
	if tr.FromDigest != r.PackageDigest {
		return fail(CodeRevocationInvalid, "tombstone from_digest %s does not match %s", tr.FromDigest, r.PackageDigest)
	}
	if tr.RevocationReason != r.Reason || tr.RevocationEffectiveTime != r.EffectiveTime || tr.ReplacementDigest != r.ReplacementDigest {
		return fail(CodeRevocationInvalid, "tombstone metadata does not match the revocation record")
	}
	if tr.TombstoneGeneration == nil || *tr.TombstoneGeneration != r.Generation {
		return fail(CodeRevocationInvalid, "tombstone generation does not match the revocation record")
	}
	return nil
}
