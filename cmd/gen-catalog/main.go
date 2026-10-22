// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// Command gen-catalog validates one capability catalog and writes its
// deterministic JCS form.  The output is the exact byte string the publisher
// signs, so two producers that agree on the object produce identical files.
//
// Usage:
//
//	gen-catalog -in catalog.json [-out catalog.canonical.json] [-force]
//
// Exit status: 0 written, 2 invalid catalog, 1 usage or I/O failure.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/varwof/register/catalog"
)

func main() {
	in := flag.String("in", "", "catalog JSON to validate")
	out := flag.String("out", "", "output file (default: -in with .canonical suffix)")
	force := flag.Bool("force", false, "replace an existing output file")
	flag.Parse()

	if *in == "" {
		fmt.Fprintln(os.Stderr, "usage: gen-catalog -in catalog.json [-out catalog.canonical.json] [-force]")
		os.Exit(1)
	}
	target := *out
	if target == "" {
		target = *in + ".canonical"
	}

	c, _, err := catalog.LoadCatalog(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-catalog: %v\n", err)
		os.Exit(2)
	}
	raw, err := catalog.CanonicalBytes(*c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-catalog: %v\n", err)
		os.Exit(1)
	}
	if err := catalog.WriteFile(target, raw, *force); err != nil {
		var pathErr *os.PathError
		if errors.As(err, &pathErr) && errors.Is(err, os.ErrExist) {
			fmt.Fprintf(os.Stderr, "gen-catalog: %s exists (use -force to replace)\n", target)
		} else {
			fmt.Fprintf(os.Stderr, "gen-catalog: %v\n", err)
		}
		os.Exit(1)
	}
	digest, _ := c.Digest()
	fmt.Printf("%s %s\n", target, digest)
}
