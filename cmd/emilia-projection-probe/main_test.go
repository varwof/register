// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package main

import "testing"

func TestDigestArtifactSetIsOrderIndependent(t *testing.T) {
	a := map[string]any{"artifact_id": "a", "subject": "alice"}
	b := map[string]any{"artifact_id": "b", "subject": "bob"}
	forward := digestArtifactSet([]map[string]any{a, b})
	reverse := digestArtifactSet([]map[string]any{b, a})
	if forward != reverse {
		t.Fatalf("set digest depends on arrival order: %s vs %s", forward, reverse)
	}
}

func TestDigestArtifactSetRejectsDuplicates(t *testing.T) {
	a := map[string]any{"artifact_id": "a"}
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate members were accepted")
		}
	}()
	digestArtifactSet([]map[string]any{a, a})
}
