// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command apply-catalog-delta verifies a signed delta against an exact base
// generation and writes the next immutable catalog.  A delta without a valid
// producer signature, or one that does not name the base by generation and
// digest, is refused; there is no "apply anyway".
//
// Usage:
//
//	apply-catalog-delta -catalog base.json -delta delta.json -signature delta.p7s
//	                   -state accepted-state.json -trust roots.pem -policy policy.json
//	                   [-out next.json] [-force]
//
// Exit status: 0 applied, 2 refused, 1 usage or I/O failure.
package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/varwof/register"
	"github.com/varwof/register/catalog"
)

func main() {
	catalogPath := flag.String("catalog", "", "base catalog JSON")
	deltaPath := flag.String("delta", "", "delta JSON")
	signaturePath := flag.String("signature", "", "detached PKCS#7 delta signature (PEM)")
	statePath := flag.String("state", "", "accepted registry state JSON")
	trustPath := flag.String("trust", "", "trust anchor PEM bundle")
	policyPath := flag.String("policy", "", "deployer trust policy JSON")
	out := flag.String("out", "", "output catalog (default: print the digest only)")
	force := flag.Bool("force", false, "replace an existing output file")
	flag.Parse()

	if *catalogPath == "" || *deltaPath == "" || *signaturePath == "" || *statePath == "" || *trustPath == "" || *policyPath == "" {
		fmt.Fprintln(os.Stderr, "usage: apply-catalog-delta -catalog base.json -delta delta.json -signature delta.p7s -state accepted-state.json -trust roots.pem -policy policy.json [-out next.json] [-force]")
		os.Exit(1)
	}

	base, _, err := catalog.LoadCatalog(*catalogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply-catalog-delta: %v\n", err)
		os.Exit(2)
	}
	deltaRaw, err := os.ReadFile(*deltaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply-catalog-delta: %v\n", err)
		os.Exit(1)
	}
	sigPEM, err := os.ReadFile(*signaturePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply-catalog-delta: %v\n", err)
		os.Exit(1)
	}
	if len(sigPEM) > 1<<20 {
		fmt.Fprintf(os.Stderr, "apply-catalog-delta: %s: signature file exceeds 1 MiB\n", *signaturePath)
		os.Exit(1)
	}
	block, _ := pem.Decode(sigPEM)
	if block == nil {
		fmt.Fprintf(os.Stderr, "apply-catalog-delta: %s: no PEM block\n", *signaturePath)
		os.Exit(1)
	}
	roots, err := register.LoadTrustRoots(*trustPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply-catalog-delta: %v\n", err)
		os.Exit(1)
	}
	policy, err := catalog.LoadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply-catalog-delta: %v\n", err)
		os.Exit(2)
	}
	state, err := catalog.LoadState(*statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply-catalog-delta: %v\n", err)
		os.Exit(2)
	}

	_, next, err := catalog.VerifySignedDeltaWithState(deltaRaw, block.Bytes, *base, roots, policy, state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply-catalog-delta: %v\n", err)
		os.Exit(2)
	}
	digest, err := next.Digest()
	if err != nil {
		fmt.Fprintf(os.Stderr, "apply-catalog-delta: %v\n", err)
		os.Exit(1)
	}
	if *out != "" {
		raw, err := catalog.CanonicalBytes(*next)
		if err != nil {
			fmt.Fprintf(os.Stderr, "apply-catalog-delta: %v\n", err)
			os.Exit(1)
		}
		if err := catalog.WriteFile(*out, raw, *force); err != nil {
			fmt.Fprintf(os.Stderr, "apply-catalog-delta: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Printf("%d %s\n", next.Generation, digest)
}
