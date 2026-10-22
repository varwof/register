// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command sign-catalog produces the detached PKCS#7 signature for one catalog
// file.  It validates the catalog first so a malformed artifact is never
// signed, and it signs the file's exact bytes (see gen-catalog for the
// deterministic form).
//
// Usage:
//
//	sign-catalog -catalog catalog.json -cert signer.pem -key signer.key [-out catalog.p7s]
//
// Exit status: 0 signed, 2 invalid catalog, 1 usage or I/O failure.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	pki "github.com/varwof/types"

	"github.com/varwof/register"
	"github.com/varwof/register/catalog"
)

func main() {
	catalogPath := flag.String("catalog", "", "catalog JSON to sign")
	certPath := flag.String("cert", "", "PEM signer certificate (plus chain)")
	keyPath := flag.String("key", "", "PEM signer private key")
	out := flag.String("out", "", "output .p7s (default: catalog + .p7s)")
	flag.Parse()

	if *catalogPath == "" || *certPath == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "usage: sign-catalog -catalog catalog.json -cert signer.pem -key signer.key [-out catalog.p7s]")
		os.Exit(1)
	}
	cat, _, err := catalog.LoadCatalog(*catalogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign-catalog: %v\n", err)
		os.Exit(2)
	}
	certs, err := register.LoadCertFile(*certPath)
	if err != nil || len(certs) == 0 {
		fmt.Fprintf(os.Stderr, "sign-catalog: load signer certificate: %v\n", err)
		os.Exit(1)
	}
	aic, err := pki.ParseAIC(certs[0])
	if err != nil || aic == nil {
		fmt.Fprintf(os.Stderr, "sign-catalog: signer certificate has no AIC: %v\n", err)
		os.Exit(2)
	}
	want := strings.TrimPrefix(cat.Producer, "principal:")
	id := aic.PrincipalUid.Identifier
	realm := aic.PrincipalUid.Realm
	if want == "" || (want != id && want != realm+":"+id) {
		fmt.Fprintf(os.Stderr, "sign-catalog: catalog producer %q does not match signer AIC %q\n", cat.Producer, realm+":"+id)
		os.Exit(2)
	}
	if err := register.SignCapability(*certPath, *keyPath, *catalogPath, *out); err != nil {
		fmt.Fprintf(os.Stderr, "sign-catalog: %v\n", err)
		os.Exit(1)
	}
}
