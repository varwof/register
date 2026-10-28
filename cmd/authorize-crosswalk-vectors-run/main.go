// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command authorize-crosswalk-vectors-run runs the CLC-D authorize cross-walk
// corpus: a carrier's native capability representation is mapped into a CLC
// grant by a pinned profile, and CLC's own authorization function decides one
// operation against it. It is evidence that a foreign capability model can be
// projected into CLC and decided by CLC, without CLC growing a second
// authorization path.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/varwof/register/internal/crosswalkvectors"
)

func main() {
	path := crosswalkvectors.AuthorizePath()
	vectors, err := crosswalkvectors.LoadAuthorize(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading authorize cross-walk vectors from %s: %v\n", path, err)
		os.Exit(1)
	}

	results := crosswalkvectors.RunAuthorize(vectors)
	pass := 0
	fmt.Printf("%-10s %-24s %-26s %-26s %-32s %s\n", "ID", "PROFILE", "EXPECT", "GOT", "NOTE", "RESULT")
	fmt.Println(strings.Repeat("-", 140))
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
		fmt.Printf("%-10s %-24s %-26s %-26s %-32s %s\n", r.ID, profile, r.Expect, r.Got, r.Note, status)
	}
	fmt.Println(strings.Repeat("-", 140))
	fmt.Printf("Total: %d | Pass: %d | Fail: %d\n", len(results), pass, len(results)-pass)
	if pass != len(results) {
		os.Exit(1)
	}
}
