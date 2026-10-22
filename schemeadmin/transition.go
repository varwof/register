// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/varwof/register/semantics"
)

// Transition is the immutable CLC-SCHEME-TRANSITION-v1 artifact.  The struct is
// the closed schema.  A transition never carries an authorization result; the
// deployer builds the management operation from it.
type Transition struct {
	Version           string `json:"@version"`
	Action            string `json:"action"`
	Scheme            string `json:"scheme"`
	Namespace         string `json:"namespace"`
	FromGeneration    *int64 `json:"from_generation,omitempty"`
	ToGeneration      int64  `json:"to_generation"`
	FromDigest        string `json:"from_digest,omitempty"`
	ToDigest          string `json:"to_digest"`
	ChangeClass       string `json:"change_class"`
	TargetCLCRevision string `json:"target_clc_revision"`

	// revoke / tombstone
	RevocationReason        string `json:"revocation_reason,omitempty"`
	RevocationEffectiveTime string `json:"revocation_effective_time,omitempty"`
	ReplacementDigest       string `json:"replacement_digest,omitempty"`
	TombstoneGeneration     *int64 `json:"tombstone_generation,omitempty"`

	// root-rotate
	NextRootPackageDigest string   `json:"next_root_package_digest,omitempty"`
	NextRootKeys          []string `json:"next_root_keys,omitempty"`
	NextRootThreshold     int      `json:"next_root_threshold,omitempty"`
}

// ParseTransition decodes a transition from its exact JSON bytes, refusing
// undeclared members.
func ParseTransition(raw []byte) (Transition, error) {
	var tr Transition
	if err := decodeClosed(raw, &tr); err != nil {
		return Transition{}, fail(CodeTransitionShape, "%s", err)
	}
	if err := ValidateTransition(tr); err != nil {
		return Transition{}, err
	}
	return tr, nil
}

// ValidateTransition checks the closed transition schema and the per-action
// required members.  State-independent checks only; Confirm compares the
// transition with the local registry state.
func ValidateTransition(tr Transition) error {
	if tr.Version != TransitionVersion {
		return fail(CodeTransitionShape, "@version must be %q, got %q", TransitionVersion, tr.Version)
	}
	switch tr.Action {
	case ActionCreate, ActionUpdate, ActionRevoke, ActionRootRotate:
	default:
		return fail(CodeTransitionShape, "action %q is not create|update|revoke|root-rotate", tr.Action)
	}
	if !schemeRe.MatchString(tr.Scheme) {
		return fail(CodeTransitionShape, "scheme %q does not match vendor/product-vN", tr.Scheme)
	}
	if !namespaceRe.MatchString(tr.Namespace) || path.Clean(tr.Namespace) != tr.Namespace {
		return fail(CodeTransitionShape, "namespace %q is not an absolute clean path", tr.Namespace)
	}
	if want := "/" + tr.Scheme; tr.Namespace != want {
		return fail(CodeNamespaceMismatch, "namespace %q must equal %q", tr.Namespace, want)
	}
	if tr.ToGeneration < 1 {
		return fail(CodeTransitionShape, "to_generation must be >= 1")
	}
	if !digestRe.MatchString(tr.ToDigest) {
		return fail(CodeTransitionShape, "to_digest %q is not a sha256 digest", tr.ToDigest)
	}
	switch tr.ChangeClass {
	case ChangePatch, ChangeMinor, ChangeMajor:
	default:
		return fail(CodeChangeClassInvalid, "change_class %q is not patch|minor|major", tr.ChangeClass)
	}
	if !clcRe.MatchString(tr.TargetCLCRevision) {
		return fail(CodeTransitionShape, "target_clc_revision %q is not CLC-N.N", tr.TargetCLCRevision)
	}
	// Action-irrelevant members are shape errors, not ignored data.  Otherwise
	// an update could carry revocation/root metadata that a consumer might read
	// while the transition is still treated as an update.
	if tr.Action != ActionRevoke {
		if tr.RevocationReason != "" || tr.RevocationEffectiveTime != "" ||
			tr.ReplacementDigest != "" || tr.TombstoneGeneration != nil {
			return fail(CodeTransitionShape, "action %q must not carry revocation metadata", tr.Action)
		}
	}
	if tr.Action != ActionRootRotate {
		if tr.NextRootPackageDigest != "" || len(tr.NextRootKeys) != 0 || tr.NextRootThreshold != 0 {
			return fail(CodeTransitionShape, "action %q must not carry next-root metadata", tr.Action)
		}
	}

	switch tr.Action {
	case ActionCreate:
		if tr.FromGeneration != nil || tr.FromDigest != "" {
			return fail(CodeCreateShape, "create must not declare from_generation/from_digest")
		}
		if tr.ToGeneration != 1 {
			return fail(CodeCreateShape, "create must target generation 1, got %d", tr.ToGeneration)
		}
		if tr.ChangeClass != ChangeMajor {
			return fail(CodeCreateShape, "create is the first package of a major line and must use change_class %q", ChangeMajor)
		}
	case ActionUpdate:
		if err := requireFrom(tr); err != nil {
			return err
		}
	case ActionRevoke:
		if err := requireFrom(tr); err != nil {
			return err
		}
		if tr.RevocationReason == "" {
			return fail(CodeTransitionShape, "revoke requires revocation_reason")
		}
		switch tr.RevocationReason {
		case "superseded", "security-defect", "publisher-withdrawal", "policy-violation", "compromised":
		default:
			return fail(CodeTransitionShape, "revocation_reason %q is not a stable reason code", tr.RevocationReason)
		}
		if tr.RevocationEffectiveTime == "" {
			return fail(CodeTransitionShape, "revoke requires revocation_effective_time")
		}
		if _, err := time.Parse(time.RFC3339, tr.RevocationEffectiveTime); err != nil {
			return fail(CodeTransitionShape, "revocation_effective_time %q is not RFC3339", tr.RevocationEffectiveTime)
		}
		if tr.TombstoneGeneration == nil {
			return fail(CodeTransitionShape, "revoke requires tombstone_generation")
		}
		if *tr.TombstoneGeneration < tr.ToGeneration {
			return fail(CodeTransitionShape, "tombstone_generation must be >= to_generation")
		}
		if tr.ReplacementDigest != "" && !digestRe.MatchString(tr.ReplacementDigest) {
			return fail(CodeTransitionShape, "replacement_digest %q is not a sha256 digest", tr.ReplacementDigest)
		}
	case ActionRootRotate:
		if err := requireFrom(tr); err != nil {
			return err
		}
		if !digestRe.MatchString(tr.NextRootPackageDigest) {
			return fail(CodeTransitionShape, "root-rotate requires next_root_package_digest")
		}
		if len(tr.NextRootKeys) == 0 {
			return fail(CodeTransitionShape, "root-rotate requires next_root_keys")
		}
		for _, k := range tr.NextRootKeys {
			if !digestRe.MatchString(k) {
				return fail(CodeTransitionShape, "next_root_keys entry %q is not a sha256 digest", k)
			}
		}
		if tr.NextRootThreshold < 1 {
			return fail(CodeTransitionShape, "root-rotate requires next_root_threshold >= 1")
		}
	}
	return nil
}

func requireFrom(tr Transition) error {
	if tr.FromGeneration == nil {
		return fail(CodeTransitionShape, "%s requires from_generation", tr.Action)
	}
	if *tr.FromGeneration < 1 {
		return fail(CodeTransitionShape, "from_generation must be >= 1")
	}
	if !digestRe.MatchString(tr.FromDigest) {
		return fail(CodeTransitionShape, "%s requires from_digest", tr.Action)
	}
	return nil
}

// TransitionDigest is the content address of a transition object.
func TransitionDigest(tr Transition) (string, error) {
	return CanonicalDigest(tr)
}

// CapabilityFor maps a transition action to its administration capability.
func CapabilityFor(action string) (string, error) {
	switch action {
	case ActionCreate:
		return CapCreate, nil
	case ActionUpdate:
		return CapUpdate, nil
	case ActionRevoke:
		return CapRevoke, nil
	case ActionRootRotate:
		return CapRootRotate, nil
	}
	return "", fail(CodeTransitionShape, "unknown action %q", action)
}

// BuildManagementOperation constructs the concrete CLC operation a deployer
// authorizes for this package/transition pair.
//
// The operation carries only the bounded dimensions the scheme declares:
// namespace, change_class, major and clc_revision.  The package and transition
// digests are integrity bindings — they are covered by the publisher's
// signature and emitted in the confirmation record — and are not operation
// parameters, because CLC-1.19 requires every operation parameter to be
// declared by the granting capability and a long-lived namespace grant cannot
// enumerate future digests.  The optional approval operation pins them exactly.
func BuildManagementOperation(pkg Package, tr Transition) (semantics.Operation, error) {
	capability, err := CapabilityFor(tr.Action)
	if err != nil {
		return semantics.Operation{}, err
	}
	op := semantics.Operation{ID: FullCapabilityID(capability), Params: map[string]any{}}

	switch tr.Action {
	case ActionCreate, ActionUpdate:
		major, err := MajorOf(pkg.Revision)
		if err != nil {
			return semantics.Operation{}, fail(CodePackageShape, "%s", err)
		}
		op.Params["namespace"] = tr.Namespace
		op.Params["change_class"] = tr.ChangeClass
		op.Params["major"] = major
		op.Params["clc_revision"] = tr.TargetCLCRevision
	case ActionRevoke:
		op.Params["namespace"] = tr.Namespace
		op.Params["package_digest"] = tr.FromDigest
		op.Params["clc_revision"] = tr.TargetCLCRevision
	case ActionRootRotate:
		if tr.FromDigest == "" {
			return semantics.Operation{}, fail(CodeTransitionShape, "root-rotate requires from_digest")
		}
		op.Params["package_digest"] = tr.FromDigest
		op.Params["clc_revision"] = tr.TargetCLCRevision
	}
	return op, nil
}

// BuildApprovalOperation constructs the exact approval operation.  It is only
// used when the deployer's trust policy requires an approval threshold, and it
// pins the package and transition digests exactly.
func BuildApprovalOperation(pkg Package, tr Transition) (semantics.Operation, error) {
	pkgDigest, err := PackageDigest(pkg)
	if err != nil {
		return semantics.Operation{}, fail(CodePackageShape, "%s", err)
	}
	trDigest, err := TransitionDigest(tr)
	if err != nil {
		return semantics.Operation{}, fail(CodeTransitionShape, "%s", err)
	}
	return semantics.Operation{
		ID: FullCapabilityID(CapApprove),
		Params: map[string]any{
			"namespace":         tr.Namespace,
			"package_digest":    pkgDigest,
			"transition_digest": trDigest,
			"clc_revision":      tr.TargetCLCRevision,
		},
	}, nil
}

// OperationDigest is the content address of a management operation.
func OperationDigest(op semantics.Operation) (string, error) {
	return CanonicalDigest(op)
}

// changeClassOrder ranks change classes so a continuity check can compare them.
func changeClassOrder(c string) int {
	switch c {
	case ChangePatch:
		return 0
	case ChangeMinor:
		return 1
	case ChangeMajor:
		return 2
	}
	return -1
}

// revisionFollows reports whether `next` is the legitimate successor of `prev`
// for the given change class.  Patch keeps major.minor, minor advances the minor
// component, major advances the major component and resets minor to 0.
func revisionFollows(prev, next, changeClass string) error {
	pmaj, err := MajorOf(prev)
	if err != nil {
		return err
	}
	pmin, err := MinorOf(prev)
	if err != nil {
		return err
	}
	nmaj, err := MajorOf(next)
	if err != nil {
		return err
	}
	nmin, err := MinorOf(next)
	if err != nil {
		return err
	}
	switch changeClass {
	case ChangePatch:
		if nmaj != pmaj || nmin != pmin {
			return fmt.Errorf("patch must keep major.minor %d.%d, got %d.%d", pmaj, pmin, nmaj, nmin)
		}
	case ChangeMinor:
		if pmin == maxIntValue {
			return fmt.Errorf("minor component %d cannot advance", pmin)
		}
		if nmaj != pmaj || nmin != pmin+1 {
			return fmt.Errorf("minor must advance %d.%d to %d.%d, got %d.%d", pmaj, pmin, pmaj, pmin+1, nmaj, nmin)
		}
	case ChangeMajor:
		if pmaj == maxIntValue {
			return fmt.Errorf("major component %d cannot advance", pmaj)
		}
		if nmaj != pmaj+1 || nmin != 0 {
			return fmt.Errorf("major must advance %d.%d to %d.0, got %d.%d", pmaj, pmin, pmaj+1, nmaj, nmin)
		}
	default:
		return fmt.Errorf("unknown change class %q", changeClass)
	}
	return nil
}

// namespaceUnder reports whether a namespace is inside one of the policy
// prefixes.  This is the deployer's local adoption policy, distinct from the
// CLC path-prefix relation that governs grant containment.
func namespaceUnder(namespace string, prefixes []string) bool {
	for _, p := range prefixes {
		if namespace == p {
			return true
		}
		if strings.HasPrefix(namespace, strings.TrimSuffix(p, "/")+"/") {
			return true
		}
	}
	return false
}
