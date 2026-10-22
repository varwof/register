// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command verify-catalog is the deployer admission path for a capability
// catalog.  It verifies the detached PKCS#7 signature over the exact catalog
// bytes, re-checks the trust chain and AIC binding, and recomputes the decision
// from the local policy and accepted-generation state.  Nothing in the artifact
// is trusted to say "verified".
//
// Usage:
//
//	verify-catalog -catalog C -signature S -trust ROOTS -policy P.json
//	               [-state S.json] [-state-out S.next.json]
//
// Exit status: 0 accept, 2 reject, 1 usage or I/O failure.
package main

import (
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/varwof/register"
	"github.com/varwof/register/catalog"
)

func main() {
	catalogPath := flag.String("catalog", "", "catalog JSON")
	sigPath := flag.String("signature", "", "detached PKCS#7 signature")
	trustPath := flag.String("trust", "", "trust root certificate or directory")
	policyPath := flag.String("policy", "", "deployer policy JSON")
	statePath := flag.String("state", "", "accepted-generation state JSON (optional)")
	stateOut := flag.String("state-out", "", "write the advanced state here on accept")
	flag.Parse()

	if *catalogPath == "" || *sigPath == "" || *trustPath == "" || *policyPath == "" {
		fmt.Fprintln(os.Stderr, "usage: verify-catalog -catalog C -signature S -trust ROOTS -policy P.json [-state S.json] [-state-out S.next.json]")
		os.Exit(1)
	}

	cat, raw, err := catalog.LoadCatalog(*catalogPath)
	if err != nil {
		emit(catalog.Result{Verdict: catalog.VerdictReject, Reason: catalog.CodeOf(err), Detail: err.Error()})
		os.Exit(2)
	}
	sigDER, err := readSignature(*sigPath)
	if err != nil {
		emit(catalog.Result{Verdict: catalog.VerdictReject, Reason: catalog.CodeSignatureInvalid, Detail: err.Error()})
		os.Exit(2)
	}
	roots, err := register.LoadTrustRoots(*trustPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-catalog: %v\n", err)
		os.Exit(1)
	}
	policy, err := catalog.LoadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-catalog: %v\n", err)
		os.Exit(1)
	}
	state, err := catalog.LoadState(*statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-catalog: %v\n", err)
		os.Exit(1)
	}

	// VerifySigned re-parses the exact bytes, verifies the detached signature
	// and then recomputes the trust decision, so the signature step cannot be
	// skipped by this command.
	res, verifyErr := catalog.VerifySigned(raw, sigDER, roots, policy, state)
	if verifyErr != nil && res.Reason == "" {
		res.Reason = catalog.CodeOf(verifyErr)
		res.Detail = verifyErr.Error()
	}
	emit(res)
	if verifyErr != nil {
		os.Exit(2)
	}
	if *stateOut != "" {
		next, err := state.Accept(*cat, res)
		if err != nil {
			fmt.Fprintf(os.Stderr, "verify-catalog: %v\n", err)
			os.Exit(1)
		}
		out, err := json.MarshalIndent(next, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "verify-catalog: %v\n", err)
			os.Exit(1)
		}
		if err := catalog.WriteFile(*stateOut, append(out, '\n'), true); err != nil {
			fmt.Fprintf(os.Stderr, "verify-catalog: %v\n", err)
			os.Exit(1)
		}
	}
}

func emit(res catalog.Result) {
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
}

func readSignature(sigPath string) ([]byte, error) {
	sigPEM, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(sigPEM)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", sigPath)
	}
	return block.Bytes, nil
}
