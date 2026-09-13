// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command evidence-vectors-run runs the CLC-E evidence-side conformance corpus
// (capability/data/_vectors/clc-v1/evidence-vectors.json) and exits non-zero on
// any mismatch, mirroring cmd/vectors-run for the authorization side.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/varwof/register/internal/evidencevectors"
)

func main() {
	path := evidencevectors.Path()
	vectors, err := evidencevectors.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading evidence vectors from %s: %v\n", path, err)
		os.Exit(1)
	}

	results := evidencevectors.Run(vectors)
	pass := 0
	fmt.Printf("%-12s %-16s %-36s %-36s %-30s %s\n", "ID", "KIND", "EXPECT", "GOT", "NOTE", "RESULT")
	fmt.Println(strings.Repeat("-", 150))
	for _, r := range results {
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
		} else {
			pass++
		}
		fmt.Printf("%-12s %-16s %-36s %-36s %-30s %s\n", r.ID, r.Kind, r.Expect, r.Got, r.Note, status)
	}
	fmt.Println(strings.Repeat("-", 150))
	fmt.Printf("Total: %d | Pass: %d | Fail: %d\n", len(results), pass, len(results)-pass)
	if pass != len(results) {
		os.Exit(1)
	}
}
