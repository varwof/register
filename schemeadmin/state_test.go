// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import (
	"testing"
)

func stateTestPackage(scheme, revision string, generation int64) Package {
	return Package{
		Version:     PackageVersion,
		Scheme:      scheme,
		Revision:    revision,
		Generation:  generation,
		CLCRevision: "CLC-1.19",
		Publisher:   "principal:test",
	}
}

func stateTestCreate(t *testing.T) (Package, Transition, ConfirmationResult) {
	t.Helper()
	pkg := stateTestPackage("std/payments-v1", "1.0", 1)
	pkgDigest, err := PackageDigest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	tr := Transition{
		Version:           TransitionVersion,
		Action:            ActionCreate,
		Scheme:            pkg.Scheme,
		Namespace:         "/std/payments-v1",
		ToGeneration:      1,
		ToDigest:          pkgDigest,
		ChangeClass:       ChangeMajor,
		TargetCLCRevision: "CLC-1.19",
	}
	trDigest, err := TransitionDigest(tr)
	if err != nil {
		t.Fatal(err)
	}
	return pkg, tr, ConfirmationResult{
		Verdict:          VerdictAccept,
		signed:           true,
		PackageDigest:    pkgDigest,
		TransitionDigest: trDigest,
	}
}

func TestRegistryStateAccept(t *testing.T) {
	pkg, tr, res := stateTestCreate(t)
	state, err := (RegistryState{}).Accept(Confirmation{Package: pkg, Transition: tr}, res)
	if err != nil {
		t.Fatalf("accept create: %v", err)
	}
	if state.Generation != 1 || state.PackageDigest != res.PackageDigest {
		t.Fatalf("state after create: %+v", state)
	}
	if _, err := state.Accept(Confirmation{Package: pkg, Transition: tr}, res); CodeOf(err) != CodeStateNotEmpty {
		t.Fatalf("replayed create: got %v", err)
	}
}

func TestRegistryStateAcceptRequiresSignedResult(t *testing.T) {
	pkg, tr, res := stateTestCreate(t)
	res.signed = false
	if _, err := (RegistryState{}).Accept(Confirmation{Package: pkg, Transition: tr}, res); CodeOf(err) != CodeStateUnverified {
		t.Fatalf("unsigned result accepted: %v", err)
	}
}

func TestRegistryStateRejectsUnsignedRevocation(t *testing.T) {
	prevDigest := "sha256:prev"
	prev := RegistryState{
		Scheme:        "std/payments-v1",
		Revision:      "1.2",
		Generation:    6,
		PackageDigest: prevDigest,
		History:       []RegistryEntry{{Generation: 6, PackageDigest: prevDigest}},
	}
	pkg := stateTestPackage("std/payments-v1", "1.3", 7)
	pkgDigest, err := PackageDigest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	fromGen := int64(6)
	tombstoneGen := int64(7)
	tr := Transition{
		Version:                 TransitionVersion,
		Action:                  ActionRevoke,
		Scheme:                  pkg.Scheme,
		Namespace:               "/std/payments-v1",
		FromGeneration:          &fromGen,
		ToGeneration:            7,
		FromDigest:              prevDigest,
		ToDigest:                pkgDigest,
		ChangeClass:             ChangePatch,
		TargetCLCRevision:       "CLC-1.19",
		RevocationReason:        "security-defect",
		RevocationEffectiveTime: "2026-10-22T00:00:00Z",
		TombstoneGeneration:     &tombstoneGen,
	}
	trDigest, err := TransitionDigest(tr)
	if err != nil {
		t.Fatal(err)
	}
	res := ConfirmationResult{
		Verdict:          VerdictAccept,
		signed:           true,
		PackageDigest:    pkgDigest,
		TransitionDigest: trDigest,
	}
	if _, err := prev.Accept(Confirmation{Package: pkg, Transition: tr}, res); CodeOf(err) != CodeRevocationInvalid {
		t.Fatalf("unsigned tombstone accepted: %v", err)
	}
}
