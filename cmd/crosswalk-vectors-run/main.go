// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command crosswalk-vectors-run runs the cross-walk corpus: native capability
// representations from other ecosystems mapped into CLC grants by a pinned
// profile, decided by the same CLC core.  It is the runnable evidence for the
// genericity claim in Appendix A.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/varwof/register/internal/crosswalkvectors"
)

func main() {
	path := crosswalkvectors.Path()
	vectors, err := crosswalkvectors.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading cross-walk vectors from %s: %v\n", path, err)
		os.Exit(1)
	}

	results := crosswalkvectors.Run(vectors)
	pass := 0
	fmt.Printf("%-10s %-24s %-22s %-30s %-34s %s\n", "ID", "PROFILE", "EXPECT", "GOT", "NOTE", "RESULT")
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
		fmt.Printf("%-10s %-24s %-22s %-30s %-34s %s\n", r.ID, profile, r.Expect, r.Got, r.Note, status)
	}
	fmt.Println(strings.Repeat("-", 150))
	fmt.Printf("Total: %d | Pass: %d | Fail: %d\n", len(results), pass, len(results)-pass)
	if pass != len(results) {
		os.Exit(1)
	}
}
