// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/varwof/register"
)

func main() {
	cert := flag.String("cert", "", "PEM certificate (signer + chain)")
	key := flag.String("key", "", "PEM private key")
	input := flag.String("in", "", "capability.json to sign")
	output := flag.String("out", "", "output .p7s file (default: in + .p7s)")
	flag.Parse()

	if *cert == "" || *key == "" || *input == "" {
		fmt.Fprintln(os.Stderr, "Usage: sign -cert <cert.pem> -key <key.pem> -in <v1.json> [-out <v1.json.p7s>]")
		os.Exit(1)
	}

	if err := register.SignCapability(*cert, *key, *input, *output); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
