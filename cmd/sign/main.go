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
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: sign -cert <signer.pem> -key <signer.key> -in <capability.json> [-out <file.p7s>]\n\n")
		fmt.Fprintf(os.Stderr, "用 PKCS#7 签署 capability/规则 JSON 文件，产出 detached .p7s 签名（默认 -in + .p7s）。\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
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
