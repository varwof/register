// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"crypto/sha256"
	"fmt"

	"github.com/varwof/register/semantics"
)

// Derivation records how one native artifact produced one projected Fact: the
// carrier, the artifact digest, the verifier/profile pins, the fact binding and
// the checks that gated it.  It makes lineage tamper-evident; it does not prove
// the carrier semantics, which remains the verifier's obligation unless the
// deployment adds attested execution or a carrier replay.
type Derivation struct {
	CarrierID             string   `json:"carrierId"`
	ArtifactDigest        Digest   `json:"artifactDigest"`
	VerifierProfileDigest Digest   `json:"verifierProfileDigest"`
	MappingProfileDigest  Digest   `json:"mappingProfileDigest,omitempty"`
	FactIndex             int      `json:"factIndex"`
	FactDigest            Digest   `json:"factDigest"`
	NativeCheckIDs        []string `json:"nativeCheckIds,omitempty"`
}

// FactBindingDigest binds a Fact value to the artifact it came from.
func FactBindingDigest(fact semantics.EvidenceFact, artifact Digest) (Digest, error) {
	raw, err := semantics.CanonicalJSON(map[string]any{
		"artifact": artifact,
		"fact":     fact,
	})
	if err != nil {
		return "", fmt.Errorf("canonical fact binding: %w", err)
	}
	sum := sha256.Sum256(raw)
	return DigestFromBytes(sum[:]), nil
}

// validateDerivations checks the derivation set against the report's facts and
// evidence records.
func validateDerivations(rep *Report) error {
	if len(rep.Derivations) == 0 {
		return nil
	}
	seen := make(map[int]bool, len(rep.Derivations))
	for i, deriv := range rep.Derivations {
		if deriv.CarrierID == "" {
			return reportFail(CodeReportDerivation, "derivation %d has no carrierId", i)
		}
		if err := deriv.ArtifactDigest.Validate(); err != nil {
			return reportFail(CodeReportDerivation, "derivation %d artifact digest: %s", i, err)
		}
		if err := deriv.VerifierProfileDigest.Validate(); err != nil {
			return reportFail(CodeReportDerivation, "derivation %d verifier profile digest: %s", i, err)
		}
		if !deriv.MappingProfileDigest.Empty() {
			if err := deriv.MappingProfileDigest.Validate(); err != nil {
				return reportFail(CodeReportDerivation, "derivation %d mapping profile digest: %s", i, err)
			}
		}
		if deriv.FactIndex < 0 || deriv.FactIndex >= len(rep.Facts) {
			return reportFail(CodeReportDerivation,
				"derivation %d factIndex %d is out of range", i, deriv.FactIndex)
		}
		if seen[deriv.FactIndex] {
			return reportFail(CodeReportDerivation,
				"fact %d has more than one derivation", deriv.FactIndex)
		}
		seen[deriv.FactIndex] = true
		if rep.Verifier != nil && deriv.VerifierProfileDigest != rep.Verifier.VerifierProfileDigest {
			return reportFail(CodeReportDerivation,
				"derivation %d verifier profile differs from the report verifier", i)
		}
		if rep.Observation != nil && !deriv.MappingProfileDigest.Empty() &&
			deriv.MappingProfileDigest != rep.Observation.MappingProfileDigest {
			return reportFail(CodeReportDerivation,
				"derivation %d mapping profile differs from the report observation", i)
		}
		want, err := FactBindingDigest(rep.Facts[deriv.FactIndex], deriv.ArtifactDigest)
		if err != nil {
			return reportFail(CodeReportDerivation, "derivation %d: %s", i, err)
		}
		if deriv.FactDigest != want {
			return reportFail(CodeReportDerivation,
				"derivation %d fact digest does not match the fact and artifact", i)
		}
		if err := derivationMatchesRecord(rep, deriv); err != nil {
			return reportFail(CodeReportDerivation, "derivation %d: %s", i, err)
		}
	}
	for i := range rep.Facts {
		if !seen[i] {
			return reportFail(CodeReportDerivation, "fact %d has no derivation", i)
		}
	}
	return nil
}

// derivationMatchesRecord requires a lineage record for the same fact index and
// artifact, with the same gating checks.
func derivationMatchesRecord(rep *Report, deriv Derivation) error {
	for _, record := range rep.EvidenceRecords {
		if record.FactIndex == nil || *record.FactIndex != deriv.FactIndex {
			continue
		}
		if record.ArtifactDigest != deriv.ArtifactDigest {
			return fmt.Errorf("artifact digest differs from the lineage record")
		}
		if len(deriv.NativeCheckIDs) > 0 && !sameStringSet(deriv.NativeCheckIDs, record.NativeCheckIDs) {
			return fmt.Errorf("gating checks differ from the lineage record")
		}
		return nil
	}
	return fmt.Errorf("no lineage record for fact index %d", deriv.FactIndex)
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, value := range a {
		seen[value]++
	}
	for _, value := range b {
		if seen[value] == 0 {
			return false
		}
		seen[value]--
	}
	return true
}
