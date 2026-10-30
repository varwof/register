// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package main

import "testing"

func TestDigestArtifactSetIsOrderIndependent(t *testing.T) {
	a := map[string]any{"artifact_id": "a", "subject": "alice", "type": "target"}
	b := map[string]any{"artifact_id": "b", "subject": "bob", "type": "target"}
	forward := digestArtifactSet([]map[string]any{a, b})
	reverse := digestArtifactSet([]map[string]any{b, a})
	if forward != reverse {
		t.Fatalf("set digest depends on arrival order: %s vs %s", forward, reverse)
	}
}

func TestDigestArtifactSetRejectsDuplicates(t *testing.T) {
	a := map[string]any{"artifact_id": "a", "type": "target"}
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate members were accepted")
		}
	}()
	digestArtifactSet([]map[string]any{a, a})
}

func TestCanonicalArtifactSetRejectsMissingType(t *testing.T) {
	if _, err := canonicalArtifactSet([]map[string]any{{"artifact_id": "a"}}); err == nil {
		t.Fatal("a member without type was accepted")
	}
}

func TestCanonicalArtifactSetRejectsMixedTypes(t *testing.T) {
	a := map[string]any{"artifact_id": "a", "type": "ep-quorum"}
	b := map[string]any{"artifact_id": "b", "type": "policy-permit"}
	if _, err := canonicalArtifactSet([]map[string]any{a, b}); err == nil {
		t.Fatal("a mixed-type set was accepted")
	}
}

func TestCanonicalArtifactSetRejectsEmpty(t *testing.T) {
	if _, err := canonicalArtifactSet(nil); err == nil {
		t.Fatal("an empty set was accepted")
	}
}
