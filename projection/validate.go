// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/varwof/register/semantics"
)

// Stable report-validation codes.  They are report-layer codes: they never
// become CLC reason codes and never change a verdict.
const (
	CodeReportShape            = "report_shape"
	CodeReportDigest           = "report_digest_invalid"
	CodeReportProfile          = "report_profile_invalid"
	CodeReportInventory        = "report_inventory_mismatch"
	CodeReportFactUnbound      = "report_fact_unbound"
	CodeReportCheckBinding     = "report_check_binding"
	CodeReportNotApplicable    = "report_not_applicable_unauthorized"
	CodeReportIncomplete       = "report_incomplete"
	CodeReportSignature        = "report_signature_invalid"
	CodeReportVerifier         = "report_verifier_mismatch"
	CodeReportStale            = "report_stale"
	CodeReportVerdict          = "report_verdict_mismatch"
	CodeReportPolicy           = "report_policy_violation"
	CodeReportSnapshotMissing  = "report_snapshot_missing"
	CodeReportSnapshotRollback = "report_snapshot_rollback"
	CodeReportSnapshotFork     = "report_snapshot_fork"
	CodeReportSnapshotSource   = "report_snapshot_source"
	CodeReportDerivation       = "report_derivation_invalid"
	CodeReportReplayMissing    = "report_replay_missing"
	CodeReportReplayMismatch   = "report_replay_mismatch"
)

// ReportVersion is the internal report schema revision. It is an
// implementation detail, not a CLC-E wire format or a published protocol.
const ReportVersion = "VARWOF-EVIDENCE-REPORT-v1"

// AssuranceLevel names what the report's evidence actually supports.
type AssuranceLevel string

const (
	// AssuranceE1 is a signed assertion: the verifier vouches for the result.
	AssuranceE1 AssuranceLevel = "E1"
	// AssuranceE2 adds derivation records binding every Fact to an artifact.
	AssuranceE2 AssuranceLevel = "E2"
	// AssuranceE3 adds execution attestation (or carrier replay) verified on the
	// signed path.
	AssuranceE3 AssuranceLevel = "E3"
)

// Valid reports whether the level is one of the closed set.
func (a AssuranceLevel) Valid() bool {
	switch a {
	case AssuranceE1, AssuranceE2, AssuranceE3:
		return true
	}
	return false
}

func (a AssuranceLevel) rank() int {
	switch a {
	case AssuranceE2:
		return 2
	case AssuranceE3:
		return 3
	default:
		return 1
	}
}

// ReportError is a report-validation failure with a stable code.
type ReportError struct {
	Code   string
	Detail string
}

func (e *ReportError) Error() string { return e.Code + ": " + e.Detail }

// CodeOf returns the stable report code of err, or "" when err is not a
// report-layer failure.
func CodeOf(err error) string {
	var reportErr *ReportError
	if errors.As(err, &reportErr) {
		return reportErr.Code
	}
	return ""
}

func reportFail(code, format string, args ...any) error {
	return &ReportError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// StatusModel states whether the profile carries status-bearing evidence at
// all.  It is explicit so "this carrier has no status" cannot be inferred from
// a forgotten declaration.
type StatusModel string

const (
	// StatusNone means the profile declares that it carries no status-bearing
	// evidence, so no status check is required.
	StatusNone StatusModel = "none"
	// StatusRequired means the profile requires native status checks and must
	// report them through NativeCheckResults.
	StatusRequired StatusModel = "required"
)

// Profile is the relying-party-facing declaration a report is evaluated
// against.  It is embedded in the report so the report is self-describing and
// can be signed as one object.
type Profile struct {
	// ID names the profile.
	ID string `json:"id"`
	// StatusModel is none or required.
	StatusModel StatusModel `json:"statusModel"`
	// RequiredChecks are the native checks the profile requires.
	RequiredChecks []string `json:"requiredChecks,omitempty"`
	// Expectations are the components the profile expects to be reported.
	Expectations []NativeCheckExpectation `json:"expectations,omitempty"`
	// NotApplicableAuthority is the verifier/profile digest allowed to author a
	// not_applicable outcome.  Empty means no NA result is accepted.
	NotApplicableAuthority Digest `json:"notApplicableAuthority,omitempty"`
	// ActionMappingDigest pins the native-to-CLC action mapping, when one is
	// used.
	ActionMappingDigest Digest `json:"actionMappingDigest,omitempty"`
	// ReasonNamespace is the prefix every native reason must carry, e.g.
	// "izmaylov".  It keeps reasons from two profiles colliding on one string.
	ReasonNamespace string `json:"reasonNamespace,omitempty"`
	// ReasonRegistryDigest pins the profile's reason-code registry.  The
	// registry itself is supplied by the relying party through
	// ReportPolicy.ReasonRegistries.
	ReasonRegistryDigest Digest `json:"reasonRegistryDigest,omitempty"`
	// ProfileDigest identifies this profile revision.
	ProfileDigest Digest `json:"profileDigest,omitempty"`
}

// Digest returns the content digest of the profile: SHA-256 over its JCS form
// with ProfileDigest cleared.  Pinning this value pins the profile content, not
// just a self-declared string.
func (p Profile) Digest() (Digest, error) {
	clone := p
	clone.ProfileDigest = ""
	raw, err := semantics.CanonicalJSON(clone)
	if err != nil {
		return "", fmt.Errorf("canonical profile: %w", err)
	}
	sum := sha256.Sum256(raw)
	return DigestFromBytes(sum[:]), nil
}

// Seal computes and stores the profile digest.
func (p *Profile) Seal() error {
	digest, err := p.Digest()
	if err != nil {
		return err
	}
	p.ProfileDigest = digest
	return nil
}

// Validate checks the declaration itself.
func (p Profile) Validate() error {
	if p.ID == "" {
		return reportFail(CodeReportProfile, "profile has no id")
	}
	switch p.StatusModel {
	case StatusNone:
		if len(p.RequiredChecks) != 0 {
			return reportFail(CodeReportProfile, "profile %q declares statusModel none with required checks", p.ID)
		}
	case StatusRequired:
		if len(p.RequiredChecks) == 0 {
			return reportFail(CodeReportProfile, "profile %q declares statusModel required without required checks", p.ID)
		}
	default:
		return reportFail(CodeReportProfile, "profile %q has statusModel %q, want none|required", p.ID, p.StatusModel)
	}
	seenChecks := make(map[string]bool, len(p.RequiredChecks))
	for _, check := range p.RequiredChecks {
		if check == "" {
			return reportFail(CodeReportProfile, "profile %q has an empty required check", p.ID)
		}
		if seenChecks[check] {
			return reportFail(CodeReportProfile, "profile %q repeats required check %q", p.ID, check)
		}
		seenChecks[check] = true
	}
	if len(p.Expectations) == 0 && p.StatusModel == StatusRequired {
		return reportFail(CodeReportProfile, "profile %q requires status checks without an expectation inventory", p.ID)
	}
	seen := make(map[string]bool, len(p.Expectations))
	for i, want := range p.Expectations {
		if err := want.validate(i); err != nil {
			return reportFail(CodeReportProfile, "%s", err)
		}
		if seen[want.key()] {
			return reportFail(CodeReportProfile, "profile %q repeats expectation %q/%q/%s",
				p.ID, want.CheckID, want.ComponentType, want.EvidenceDigest)
		}
		seen[want.key()] = true
	}
	if p.ReasonNamespace != "" && !validReasonNamespace(p.ReasonNamespace) {
		return reportFail(CodeReportProfile,
			"profile %q reasonNamespace %q is not [a-z0-9][a-z0-9.-]*", p.ID, p.ReasonNamespace)
	}
	if !p.ReasonRegistryDigest.Empty() {
		if p.ReasonNamespace == "" {
			return reportFail(CodeReportProfile,
				"profile %q pins a reason registry without a reasonNamespace", p.ID)
		}
		if err := p.ReasonRegistryDigest.Validate(); err != nil {
			return reportFail(CodeReportProfile, "profile %q reason registry digest: %s", p.ID, err)
		}
	}
	if !p.ProfileDigest.Empty() {
		want, err := p.Digest()
		if err != nil {
			return reportFail(CodeReportProfile, "profile %q: %s", p.ID, err)
		}
		if want != p.ProfileDigest {
			return reportFail(CodeReportProfile,
				"profile %q digest does not match its content", p.ID)
		}
	}
	for name, digest := range map[string]Digest{
		"notApplicableAuthority": p.NotApplicableAuthority,
		"actionMappingDigest":    p.ActionMappingDigest,
		"profileDigest":          p.ProfileDigest,
	} {
		if digest.Empty() {
			continue
		}
		if err := digest.Validate(); err != nil {
			return reportFail(CodeReportProfile, "profile %q %s: %s", p.ID, name, err)
		}
	}
	return nil
}

// validate checks one expectation record.
func (e NativeCheckExpectation) validate(index int) error {
	if e.CheckID == "" {
		return fmt.Errorf("expectation %d has no checkId", index)
	}
	if e.ComponentType == "" {
		return fmt.Errorf("expectation %d (%s) has no componentType", index, e.CheckID)
	}
	if err := e.EvidenceDigest.Validate(); err != nil {
		return fmt.Errorf("expectation %d (%s) evidence digest: %w", index, e.CheckID, err)
	}
	return nil
}

// VerifierIdentity is the report producer's declared identity.  A signed
// report binds the signing certificate to this name and key, so the signature
// and the claimed verifier cannot drift apart.
type VerifierIdentity struct {
	// Principal is the AIC principal name, either "principal:<id>" or
	// "<realm>:<id>".
	Principal string `json:"principal"`
	// VerifierProfileDigest identifies the verifier's profile revision.
	VerifierProfileDigest Digest `json:"verifierProfileDigest,omitempty"`
}

// Validate checks the declared identity.
func (v VerifierIdentity) Validate() error {
	if strings.TrimSpace(v.Principal) == "" {
		return reportFail(CodeReportVerifier, "verifier identity has no principal")
	}
	if v.VerifierProfileDigest.Empty() {
		return reportFail(CodeReportVerifier, "verifier identity has no profile digest")
	}
	if err := v.VerifierProfileDigest.Validate(); err != nil {
		return reportFail(CodeReportVerifier, "verifier identity profile digest: %s", err)
	}
	return nil
}

// ReportPolicy is the deployer-side bar applied on top of structural
// validation.
type ReportPolicy struct {
	// RequireProfile rejects a report that does not embed a profile.
	RequireProfile bool
	// RequireComplete rejects a report whose native-check report is incomplete.
	RequireComplete bool
	// Roots are the trust anchors a report signer must chain to.  Empty means
	// no signature can be verified; a caller that wants an unsigned report uses
	// ValidateEvidenceReport instead.
	Roots []*x509.Certificate
	// VerifierPrincipals, when non-empty, is the allowlist of principals a
	// report may claim.
	VerifierPrincipals []string
	// ProfileDigest, when set, must equal the embedded profile's digest.
	ProfileDigest Digest
	// RequirementDigest, when set, pins the CLC requirement the report was
	// evaluated against.  Without it a verifier could swap in a weaker
	// requirement and still produce a self-consistent verdict.
	RequirementDigest *semantics.Digest
	// VerifierProfileDigests, when non-empty, is the allowlist of verifier
	// profile revisions a report may claim.
	VerifierProfileDigests []Digest
	// SnapshotSources, when non-empty, is the allowlist of status-snapshot
	// authorities.  A verifier must not be able to mint a new source string to
	// escape rollback comparison.
	SnapshotSources []string
	// ReasonRegistries maps a profile's reason-registry digest to its allowed
	// codes.  A profile that pins a registry is refused when the map is absent.
	ReasonRegistries map[Digest]map[string]bool
	// RequireDerivations rejects a report that carries no derivation records.
	RequireDerivations bool
	// Artifacts maps an artifact digest to its bytes.  When supplied, each
	// derivation's artifact is hashed and compared.
	Artifacts map[Digest][]byte
	// RequireArtifacts rejects a derivation whose artifact bytes are absent.
	RequireArtifacts bool
	// AttestationVerifier checks an execution attestation against the signed
	// payload digest.  The report layer supplies the hook, not a TEE library.
	AttestationVerifier func(Attestation, Digest) error
	// RequireAttestation rejects a signed report without an attestation.
	RequireAttestation bool
	// MinAssurance is the lowest evidence level the deployer accepts.
	MinAssurance AssuranceLevel
	// RequiredCheckIDs pins the checks the deployer requires, independently of
	// whatever the report declares.  Without it, a profile-less report's
	// required set is only the signer's own claim.
	RequiredCheckIDs []string
	// attestationVerified is set by VerifySignedReport after the attestation
	// hook succeeds; E3 reports are refused without it.
	attestationVerified bool
	// MaxAge bounds how old a report may be, measured from AppraisalTime.
	MaxAge time.Duration
	// MaxClockSkew is the tolerated forward error for AppraisalTime.  Zero
	// means the default five minutes.
	MaxClockSkew time.Duration
	// TimestampRoots are the pinned timestamp-authority trust anchors.
	TimestampRoots []*x509.Certificate
	// RequireTimestamp rejects an envelope without a verified timestamp
	// assertion.
	RequireTimestamp bool
	// TimestampClockSkew is the tolerated forward error for the asserted
	// instant; zero means the default.
	TimestampClockSkew time.Duration
	// Now is the verification instant (zero means the wall clock).
	Now time.Time
	// Snapshots is the deployer's accepted snapshot state.  A report may only
	// advance it, never roll it back or fork it.
	Snapshots SnapshotState
	// RequireSnapshotBinding rejects a success/failed result that does not
	// declare which status snapshot it used.
	RequireSnapshotBinding bool
	// ReplayEvidence maps a report's replayDigest to the raw replay
	// artifact the verifier re-derives the result from.
	ReplayEvidence map[Digest][]byte
	// RequireReplay rejects a result that carries no replay digest.
	RequireReplay bool
}

// ValidateEvidenceReport checks the report's own shape and internal
// consistency.  It never asserts that the native checks succeeded, and it does
// not require completeness: an incomplete report is still a valid report.
func ValidateEvidenceReport(rep *Report) error {
	if rep == nil {
		return reportFail(CodeReportShape, "report is nil")
	}
	var profile *Profile
	if rep.Profile != nil {
		profile = rep.Profile
		if err := profile.Validate(); err != nil {
			return err
		}
	}
	// Digest syntax is checked before the full result validation so a
	// non-canonical digest gets its own stable code rather than the generic
	// shape error.
	for i, result := range rep.NativeCheckResults {
		for name, digest := range map[string]Digest{
			"evidence digest":         result.EvidenceDigest,
			"verifier/profile digest": result.VerifierProfileDigest,
			"trust-snapshot digest":   result.TrustSnapshotDigest,
			"status-snapshot digest":  result.StatusSnapshotDigest,
			"aec replay digest":       result.ReplayDigest,
		} {
			if digest.Empty() {
				continue
			}
			if err := digest.Validate(); err != nil {
				return reportFail(CodeReportDigest, "native check result %d (%s) %s: %s",
					i, result.CheckID, name, err)
			}
		}
	}
	if rep.Version != ReportVersion {
		return reportFail(CodeReportShape,
			"report @version %q is not %q", rep.Version, ReportVersion)
	}
	if !rep.Assurance.Valid() {
		return reportFail(CodeReportShape, "report assurance %q is not E1|E2|E3", rep.Assurance)
	}
	results, err := normalizeResults(rep.NativeCheckResults)
	if err != nil {
		return reportFail(CodeReportShape, "%s", err)
	}
	for i, record := range rep.EvidenceRecords {
		if err := record.ArtifactDigest.Validate(); err != nil {
			return reportFail(CodeReportDigest, "evidence record %d artifact digest: %s", i, err)
		}
		if !record.NativeRecordDigest.Empty() {
			if err := record.NativeRecordDigest.Validate(); err != nil {
				return reportFail(CodeReportDigest, "evidence record %d native record digest: %s", i, err)
			}
		}
		if !record.RelationTupleDigest.Empty() {
			if err := record.RelationTupleDigest.Validate(); err != nil {
				return reportFail(CodeReportDigest, "evidence record %d relation tuple digest: %s", i, err)
			}
		}
	}
	if rep.Observation != nil && !rep.Observation.MappingProfileDigest.Empty() {
		if err := rep.Observation.MappingProfileDigest.Validate(); err != nil {
			return reportFail(CodeReportDigest, "observation mapping profile digest: %s", err)
		}
	}
	if profile != nil {
		if err := validateAssessment(rep, profile, results); err != nil {
			return err
		}
		if err := validateNotApplicableAuthority(profile, results); err != nil {
			return err
		}
	}
	if rep.Requirement != nil && rep.ProjectedRequirementDigest != nil {
		want, err := rep.Requirement.Digest()
		if err != nil {
			return reportFail(CodeReportShape, "requirement digest: %s", err)
		}
		if !want.Equal(*rep.ProjectedRequirementDigest) {
			return reportFail(CodeReportDigest,
				"projected requirement digest does not match the requirement")
		}
	}
	if profile != nil {
		if err := validateReasonCodes(profile, results); err != nil {
			return err
		}
	}
	if rep.Verifier != nil {
		if err := rep.Verifier.Validate(); err != nil {
			return err
		}
		for _, result := range results {
			if result.Verifier != rep.Verifier.Principal {
				return reportFail(CodeReportVerifier,
					"check %q names verifier %q, report names %q",
					result.CheckID, result.Verifier, rep.Verifier.Principal)
			}
			if result.VerifierProfileDigest != rep.Verifier.VerifierProfileDigest {
				return reportFail(CodeReportVerifier,
					"check %q profile digest does not match the report verifier", result.CheckID)
			}
		}
	}
	if rep.AppraisalTime == nil {
		return reportFail(CodeReportShape, "report has no appraisal time")
	}
	if rep.AppraisalTime.IsZero() {
		return reportFail(CodeReportShape, "report appraisal time is the zero instant")
	}
	// A record that names an observation must name the report's observation.
	if rep.Observation != nil {
		identity := rep.Observation.NativeActionDigest
		if identity == "" {
			identity = rep.Observation.CLCActionID
		}
		for i, record := range rep.EvidenceRecords {
			if record.ObservationID == "" {
				continue
			}
			if identity == "" || record.ObservationID != identity {
				return reportFail(CodeReportCheckBinding,
					"evidence record %d names observation %q, report observation is %q",
					i, record.ObservationID, identity)
			}
		}
	} else {
		for i, record := range rep.EvidenceRecords {
			if record.ObservationID != "" {
				return reportFail(CodeReportCheckBinding,
					"evidence record %d names observation %q but the report has none",
					i, record.ObservationID)
			}
		}
	}
	// A profile-based report must carry lineage even when it has no records:
	// otherwise a profile could drop the records and keep the Facts.  A
	// profile-less report keeps the legacy shape, where facts are supplied
	// without an artifact mapping.
	if len(rep.EvidenceRecords) > 0 || rep.Profile != nil {
		if err := validateLineage(rep, results); err != nil {
			return err
		}
	}
	if err := validateDerivations(rep); err != nil {
		return err
	}
	return nil
}

// VerifyEvidenceReport is the final gate: structural validation plus the
// deployer's policy.  A profile that declares status checks required cannot
// pass while the report says its native checks are incomplete.
func VerifyEvidenceReport(rep *Report, policy ReportPolicy) error {
	if err := ValidateEvidenceReport(rep); err != nil {
		return err
	}
	// A deployer minimum is configuration, not report input: an unknown level
	// must be a refusal, never a silent fall back to the lowest rank.
	if policy.MinAssurance != "" && !policy.MinAssurance.Valid() {
		return reportFail(CodeReportPolicy,
			"deployer minimum assurance %q is not E1|E2|E3", policy.MinAssurance)
	}
	if policy.RequireProfile && rep.Profile == nil {
		return reportFail(CodeReportProfile, "report does not embed a profile")
	}
	// Recompute completeness instead of trusting the signed boolean.
	required := append([]string(nil), rep.RequiredCheckIDs...)
	required = unionStrings(required, policy.RequiredCheckIDs)
	if rep.Profile != nil {
		required = unionStrings(required, rep.Profile.RequiredChecks)
	}
	complete := requiredChecksComplete(required, rep.NativeCheckResults)
	if rep.Profile != nil && len(rep.Profile.Expectations) > 0 {
		if rep.NativeCheckAssessment == nil || !rep.NativeCheckAssessment.Complete {
			complete = false
		}
	}
	if complete != rep.NativeChecksComplete {
		return reportFail(CodeReportIncomplete,
			"nativeChecksComplete does not match the declared checks and results")
	}
	if !policy.ProfileDigest.Empty() {
		if rep.Profile == nil || rep.Profile.ProfileDigest != policy.ProfileDigest {
			return reportFail(CodeReportPolicy, "report profile digest is not the pinned profile")
		}
	}
	if policy.RequirementDigest != nil {
		if rep.ProjectedRequirementDigest == nil ||
			!rep.ProjectedRequirementDigest.Equal(*policy.RequirementDigest) {
			return reportFail(CodeReportPolicy, "report requirement digest is not the pinned requirement")
		}
	}
	if rep.Profile != nil && !rep.Profile.ReasonRegistryDigest.Empty() {
		registry, ok := policy.ReasonRegistries[rep.Profile.ReasonRegistryDigest]
		if !ok {
			return reportFail(CodeReportPolicy, "reason registry is not supplied")
		}
		for _, result := range rep.NativeCheckResults {
			if result.Reason == "" {
				continue
			}
			code, ok := reasonCode(rep.Profile.ReasonNamespace, result.Reason)
			if !ok || !registry[code] {
				return reportFail(CodeReportPolicy,
					"reason %q is not in the pinned registry", result.Reason)
			}
		}
	}
	if rep.Assurance.rank() >= AssuranceE2.rank() && len(rep.Derivations) == 0 {
		return reportFail(CodeReportPolicy,
			"assurance %s requires derivation records", rep.Assurance)
	}
	if rep.Assurance == AssuranceE3 && !policy.attestationVerified {
		return reportFail(CodeReportPolicy,
			"assurance E3 requires a verified attestation or replay")
	}
	if policy.MinAssurance != "" && rep.Assurance.rank() < policy.MinAssurance.rank() {
		return reportFail(CodeReportPolicy,
			"report assurance %s is below the required %s", rep.Assurance, policy.MinAssurance)
	}
	if policy.RequireDerivations && len(rep.Derivations) == 0 {
		return reportFail(CodeReportPolicy, "report carries no derivation records")
	}
	for _, deriv := range rep.Derivations {
		raw, ok := policy.Artifacts[deriv.ArtifactDigest]
		if !ok {
			if policy.RequireArtifacts {
				return reportFail(CodeReportPolicy,
					"artifact %s is not supplied", deriv.ArtifactDigest)
			}
			continue
		}
		sum := sha256.Sum256(raw)
		if DigestFromBytes(sum[:]) != deriv.ArtifactDigest {
			return reportFail(CodeReportPolicy,
				"artifact %s does not hash to its digest", deriv.ArtifactDigest)
		}
	}
	if len(policy.VerifierProfileDigests) > 0 {
		allowed := false
		if rep.Verifier != nil {
			for _, digest := range policy.VerifierProfileDigests {
				if rep.Verifier.VerifierProfileDigest == digest {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			return reportFail(CodeReportPolicy, "verifier profile is not in the allowlist")
		}
	}
	if rep.Profile != nil && rep.Profile.StatusModel == StatusRequired && !rep.NativeChecksComplete {
		return reportFail(CodeReportIncomplete,
			"profile %q requires native checks but the report is incomplete", rep.Profile.ID)
	}
	if policy.RequireComplete && !rep.NativeChecksComplete {
		return reportFail(CodeReportIncomplete, "native checks are incomplete")
	}
	// Lifecycle policy must not be silently ignored on the unsigned path.
	if policy.Snapshots != nil || len(policy.ReplayEvidence) > 0 ||
		len(policy.SnapshotSources) > 0 || policy.RequireSnapshotBinding || policy.RequireReplay {
		if _, err := CheckReportLifecycle(rep, policy); err != nil {
			return err
		}
	}
	return nil
}

// validateAssessment requires the embedded assessment to be exactly the
// comparison the profile declares, so a caller cannot ship a friendlier one.
func validateAssessment(rep *Report, profile *Profile, results []NativeCheckResult) error {
	if len(profile.Expectations) == 0 {
		if rep.NativeCheckAssessment != nil {
			return reportFail(CodeReportInventory,
				"report carries an assessment but profile %q declares no inventory", profile.ID)
		}
		return nil
	}
	want := AssessNativeChecks(profile.Expectations, results)
	if rep.NativeCheckAssessment == nil {
		return reportFail(CodeReportInventory, "report has no assessment for the declared inventory")
	}
	if !reflect.DeepEqual(*rep.NativeCheckAssessment, want) {
		return reportFail(CodeReportInventory, "report assessment does not match the declared inventory")
	}
	return nil
}

// validateNotApplicableAuthority refuses a not_applicable result that the
// pinned profile did not author.  An artifact issuer or presenter must not be
// able to turn a required check into "does not apply".
func validateNotApplicableAuthority(profile *Profile, results []NativeCheckResult) error {
	for _, result := range results {
		if result.Outcome != NativeCheckNotApplicable {
			continue
		}
		if profile.NotApplicableAuthority.Empty() ||
			result.VerifierProfileDigest != profile.NotApplicableAuthority {
			return reportFail(CodeReportNotApplicable,
				"check %q reports not_applicable without profile authority", result.CheckID)
		}
	}
	return nil
}

// factKey is the value identity of an EvidenceFact.  It is only used to match
// report facts with their lineage record, never to change CLC evaluation.
func factKey(f semantics.EvidenceFact) string {
	return f.Type + "\x00" + f.Subject + "\x00" +
		strconv.FormatBool(f.Verified) + "\x00" +
		f.IssuedAt.UTC().Format(time.RFC3339Nano)
}

// validateLineage requires a bijection between the reported Facts and the
// evidence records, and requires every gating check id to name a result over
// the same artifact digest.
func validateLineage(rep *Report, results []NativeCheckResult) error {
	used := make(map[int]bool, len(rep.Facts))
	for i, record := range rep.EvidenceRecords {
		if record.Fact == nil {
			if record.FactIndex != nil {
				return reportFail(CodeReportFactUnbound,
					"evidence record %d names a fact index but no fact", i)
			}
			if len(record.NativeCheckIDs) > 0 {
				if err := checkIDsBoundToArtifact(record.NativeCheckIDs, record.ArtifactDigest, results); err != nil {
					return reportFail(CodeReportCheckBinding, "evidence record %d: %s", i, err)
				}
			}
			continue
		}
		if record.FactIndex == nil {
			return reportFail(CodeReportFactUnbound,
				"evidence record %d names a fact without factIndex", i)
		}
		index := *record.FactIndex
		if index < 0 || index >= len(rep.Facts) {
			return reportFail(CodeReportFactUnbound,
				"evidence record %d factIndex %d is out of range", i, index)
		}
		if used[index] {
			return reportFail(CodeReportFactUnbound,
				"fact %d is bound by more than one evidence record", index)
		}
		used[index] = true
		if factKey(rep.Facts[index]) != factKey(*record.Fact) {
			return reportFail(CodeReportFactUnbound,
				"evidence record %d fact does not match factIndex %d", i, index)
		}
		if len(record.NativeCheckIDs) == 0 {
			return reportFail(CodeReportCheckBinding,
				"evidence record %d has a Fact but no gating check", i)
		}
		if err := checkIDsBoundToArtifact(record.NativeCheckIDs, record.ArtifactDigest, results); err != nil {
			return reportFail(CodeReportCheckBinding, "evidence record %d: %s", i, err)
		}
	}
	for i := range rep.Facts {
		if !used[i] {
			return reportFail(CodeReportFactUnbound,
				"fact %d has no lineage record", i)
		}
	}
	return nil

}

// checkIDsBoundToArtifact requires each named check to have at least one
// result whose evidence digest is the record's artifact digest.
func checkIDsBoundToArtifact(ids []string, artifact Digest, results []NativeCheckResult) error {
	for _, id := range ids {
		bound := false
		for _, result := range results {
			if result.CheckID == id && result.EvidenceDigest == artifact {
				bound = true
				break
			}
		}
		if !bound {
			return fmt.Errorf("check %q has no result over artifact %s", id, artifact)
		}
	}
	return nil
}

// validReasonNamespace accepts [a-z0-9][a-z0-9.-]*.
func validReasonNamespace(ns string) bool {
	if ns == "" {
		return false
	}
	for i := 0; i < len(ns); i++ {
		c := ns[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// reasonCode splits "<namespace>:<code>" and validates the code shape.
func reasonCode(ns, reason string) (string, bool) {
	if ns == "" {
		return "", false
	}
	prefix := ns + ":"
	if len(reason) <= len(prefix) || reason[:len(prefix)] != prefix {
		return "", false
	}
	code := reason[len(prefix):]
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == ':' || c == '-'):
		default:
			return "", false
		}
	}
	return code, true
}

// validateReasonCodes enforces the profile's reason namespace.
func validateReasonCodes(profile *Profile, results []NativeCheckResult) error {
	for _, result := range results {
		if result.Reason == "" {
			continue
		}
		if profile.ReasonNamespace == "" {
			return reportFail(CodeReportProfile,
				"check %q has reason %q but profile %q declares no reasonNamespace",
				result.CheckID, result.Reason, profile.ID)
		}
		if _, ok := reasonCode(profile.ReasonNamespace, result.Reason); !ok {
			return reportFail(CodeReportProfile,
				"check %q reason %q is outside namespace %q",
				result.CheckID, result.Reason, profile.ReasonNamespace)
		}
	}
	return nil
}
