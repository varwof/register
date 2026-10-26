// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command native-check-vectors-run evaluates the language-neutral
// NativeCheckExpectation/NativeCheckAssessment corpus with the Go reference
// implementation.  The corpus is shared with the Python and TypeScript runners;
// only the inventory comparison is exercised, never CLC requirement evaluation.
//
// The corpus path comes from CLC_NATIVE_CHECK_CASES or the first argument.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/varwof/register/projection"
)

type corpusExpectation struct {
	CheckID        string            `json:"checkId"`
	ComponentType  string            `json:"componentType"`
	EvidenceDigest projection.Digest `json:"evidenceDigest"`
}

type corpusResult struct {
	CheckID        string                        `json:"checkId"`
	ComponentType  string                        `json:"componentType"`
	EvidenceDigest projection.Digest             `json:"evidenceDigest"`
	Outcome        projection.NativeCheckOutcome `json:"outcome"`
}

type corpusCase struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Expected []corpusExpectation `json:"expected"`
	Results  []corpusResult      `json:"results"`
	Want     string              `json:"want"`
}

type corpus struct {
	Version string       `json:"@version"`
	Cases   []corpusCase `json:"cases"`
}

func main() {
	path := os.Getenv("CLC_NATIVE_CHECK_CASES")
	if path == "" && len(os.Args) > 1 {
		path = os.Args[1]
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "usage: native-check-vectors-run <cases.json> (or CLC_NATIVE_CHECK_CASES)")
		os.Exit(2)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read corpus: %v\n", err)
		os.Exit(2)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		fmt.Fprintf(os.Stderr, "parse corpus: %v\n", err)
		os.Exit(2)
	}

	failures := 0
	for _, tc := range c.Cases {
		expected := make([]projection.NativeCheckExpectation, 0, len(tc.Expected))
		for _, e := range tc.Expected {
			expected = append(expected, projection.NativeCheckExpectation{
				CheckID:        e.CheckID,
				ComponentType:  e.ComponentType,
				EvidenceDigest: e.EvidenceDigest,
			})
		}
		results := make([]projection.NativeCheckResult, 0, len(tc.Results))
		for _, r := range tc.Results {
			results = append(results, projection.NativeCheckResult{
				CheckID:        r.CheckID,
				ComponentType:  r.ComponentType,
				EvidenceDigest: r.EvidenceDigest,
				Outcome:        r.Outcome,
			})
		}
		assessment := projection.AssessNativeChecks(expected, results)
		got := fmt.Sprintf("complete=%t,missing=%d,unexpected=%d,conflicting=%d",
			assessment.Complete,
			len(assessment.MissingExpectations),
			len(assessment.UnexpectedResults),
			len(assessment.ConflictingResults),
		)
		status := "PASS"
		if got != tc.Want {
			status = "FAIL"
			failures++
		}
		fmt.Printf("%s %s %-52s want=%s got=%s\n", status, tc.ID, tc.Name, tc.Want, got)
	}
	if failures != 0 {
		fmt.Fprintf(os.Stderr, "%d case(s) failed\n", failures)
		os.Exit(1)
	}
}
