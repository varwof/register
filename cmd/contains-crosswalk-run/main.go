// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command contains-crosswalk-run runs the CLC-D containment cross-walk corpus:
// a native representation from another ecosystem is mapped into a CLC grant by
// a pinned profile on each side, and semantics.Contains decides the
// (parent, child) pair.  It is the runnable evidence that CLC-D's attenuation
// boundary applies to a carrier's own representation without changing CLC.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/varwof/register/internal/crosswalkvectors"
)

func main() {
	path := crosswalkvectors.ContainPath()
	vectors, err := crosswalkvectors.LoadContain(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading CLC-D cross-walk vectors from %s: %v\n", path, err)
		os.Exit(1)
	}

	results := crosswalkvectors.RunContain(vectors)
	pass := 0
	fmt.Printf("%-10s %-24s %-24s %-24s %-40s %s\n", "ID", "PROFILE", "EXPECT", "GOT", "NOTE", "RESULT")
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
		fmt.Printf("%-10s %-24s %-24s %-24s %-40s %s\n", r.ID, profile, r.Expect, r.Got, r.Note, status)
	}
	fmt.Println(strings.Repeat("-", 150))
	fmt.Printf("Total: %d | Pass: %d | Fail: %d\n", len(results), pass, len(results)-pass)
	if pass != len(results) {
		os.Exit(1)
	}
}
