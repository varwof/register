// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command mode-lattice-vectors-run runs the AIC-JWT DA delegation-mode
// pre-check corpus (core §13.4.5).  Delegation mode is a binding-profile
// concern, never a Contains argument: the profile owns the lattice order
// (AIC-JWT: authorized < representative) and reports
// delegation_mode_not_narrower itself.  This runner is the runnable evidence
// that the profile-owned code now has a corpus endpoint.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/varwof/register/internal/crosswalkvectors"
)

func main() {
	path := crosswalkvectors.ModePath()
	vectors, err := crosswalkvectors.LoadMode(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading AIC-JWT DA mode-lattice vectors from %s: %v\n", path, err)
		os.Exit(1)
	}

	results := crosswalkvectors.RunMode(vectors)
	pass := 0
	fmt.Printf("%-12s %-22s %-30s %-30s %-28s %s\n", "ID", "PROFILE", "EXPECT", "GOT", "NOTE", "RESULT")
	fmt.Println(strings.Repeat("-", 150))
	for i, r := range results {
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
		} else {
			pass++
		}
		profile := ""
		if i < len(vectors) {
			profile = vectors[i].Profile
		}
		fmt.Printf("%-12s %-22s %-30s %-30s %-28s %s\n", r.ID, profile, r.Expect, r.Got, r.Note, status)
	}
	fmt.Println(strings.Repeat("-", 150))
	fmt.Printf("Total: %d | Pass: %d | Fail: %d\n", len(results), pass, len(results)-pass)
	if pass != len(results) {
		os.Exit(1)
	}
}
