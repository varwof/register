// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"

	"github.com/varwof/register"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: verify -in <capability.json> [-sig <file.p7s>] -CA <root.pem|dir>\n\n")
		fmt.Fprintf(os.Stderr, "校验 detached PKCS#7 签名是否链到给定信任根；失败即非零退出。\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	input := flag.String("in", "", "capability.json to verify")
	sig := flag.String("sig", "", ".p7s signature file (default: in + .p7s)")
	ca := flag.String("CA", "", "trust root certificate(s) file or directory")
	flag.Parse()

	if *input == "" {
		fmt.Fprintln(os.Stderr, "Usage: verify -in <v1.json> [-sig <v1.json.p7s>] [-CA <root-ca.pem>]")
		os.Exit(1)
	}

	sigPath := *sig
	if sigPath == "" {
		sigPath = *input + ".p7s"
	}

	var trustRoots []*x509.Certificate
	if *ca != "" {
		var err error
		trustRoots, err = register.LoadTrustRoots(*ca)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading trust roots: %v\n", err)
			os.Exit(1)
		}
	}

	err := register.VerifyCapabilityPKCS7(*input, trustRoots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK: signature verified")
}
