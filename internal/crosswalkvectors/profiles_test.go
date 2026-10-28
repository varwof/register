// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package crosswalkvectors

import (
	"os"
	"sort"
	"strings"
	"testing"
)

// TestProfileDeclarations runs the §13.8.1 (rev CLC-1.18) obligations 6 and 7
// over the declaration file: the live declarations must conform, every profile
// the corpora use must be declared exactly once, the illustrative declarations
// that do claim a basis must conform, and each negative case must be refused
// with its declared reason code.
func TestProfileDeclarations(t *testing.T) {
	path := DeclarationsPath()
	if _, err := os.Stat(path); err != nil {
		alt := "../../../capability/data/_vectors/clc-v1/profile-declarations.json"
		if _, err := os.Stat(alt); err != nil {
			t.Skipf("profile declarations unavailable (%v); set CLC_PROFILE_DECLARATIONS to run them", err)
		}
		path = alt
	}
	d, err := LoadDeclarations(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(d.Declarations) == 0 {
		t.Fatal("no declarations")
	}

	// obligation 6 and 7, per live declaration
	for _, dec := range d.Declarations {
		if issues := CheckDeclaration(dec); len(issues) > 0 {
			t.Errorf("%s: %s", dec.Profile, strings.Join(issues, ","))
		}
	}

	// corpus coverage: exactly one declaration per profile the corpora use
	used, err := ProfilesInCorpora(
		"../capability/data/_vectors/clc-v1/crosswalk-vectors.json",
		"../capability/data/_vectors/clc-d/containment-crosswalk-vectors.json",
		"../capability/data/_vectors/clc-d/authorize-crosswalk-vectors.json",
	)
	if err != nil {
		alt := []string{
			"../../../capability/data/_vectors/clc-v1/crosswalk-vectors.json",
			"../../../capability/data/_vectors/clc-d/containment-crosswalk-vectors.json",
			"../../../capability/data/_vectors/clc-d/authorize-crosswalk-vectors.json",
		}
		used, err = ProfilesInCorpora(alt...)
		if err != nil {
			t.Skipf("cross-walk corpora unavailable (%v); coverage check skipped", err)
		}
	}
	if issues := CheckCoverage(d, used); len(issues) > 0 {
		keys := make([]string, 0, len(issues))
		for k := range issues {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.Errorf("coverage %s: %s", k, strings.Join(issues[k], ","))
		}
	}

	// the accept path, pinned by the illustrative declarations
	if len(d.Examples) == 0 {
		t.Error("no illustrative declaration pins the accept path")
	}
	for _, ex := range d.Examples {
		if issues := CheckDeclaration(ex); len(issues) > 0 {
			t.Errorf("example %s: %s", ex.Profile, strings.Join(issues, ","))
		}
	}

	// the reject path, one declared reason code per negative case
	if len(d.NegativeCases) == 0 {
		t.Error("no negative cases")
	}
	for _, nc := range d.NegativeCases {
		got := CheckDeclaration(nc.Declaration)
		if !contains(got, nc.Want) {
			t.Errorf("%s: want %s, got %v", nc.ID, nc.Want, got)
		}
	}
}
