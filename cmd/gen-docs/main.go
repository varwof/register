// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/varwof/register"
)

func main() {
	var (
		out = flag.String("out", "", "output markdown path (default: <scheme_dir>/<product>-capabilities.md)")
		all = flag.Bool("all", false, "generate docs for all schemes under a directory")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: gen-docs [flags] <scheme.json> [more.json ...]\n\n")
		fmt.Fprintf(os.Stderr, "从 capability.json 生成 markdown 权限说明文档（AI/人可读）。\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	if *all {
		// Directory mode: load all schemes and generate docs for each
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Error: -all mode accepts only one directory argument")
			os.Exit(2)
		}
		schemes, err := register.LoadAllSchemes(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if len(schemes) == 0 {
			fmt.Fprintf(os.Stderr, "Error: no schemes found under %s\n", args[0])
			os.Exit(1)
		}
		for _, def := range schemes {
			outPath := *out
			if outPath == "" {
				outPath = filepath.Join(args[0], def.Vendor, def.Product, def.Product+"-capabilities.md")
			}
			if err := register.GenDocsToFile(def, outPath); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Generated %s\n", outPath)
		}
		return
	}

	for _, p := range args {
		def, err := register.LoadScheme(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", p, err)
			os.Exit(1)
		}
		outPath := *out
		if outPath == "" {
			dir := filepath.Dir(p)
			outPath = filepath.Join(dir, def.Product+"-capabilities.md")
		}
		if err := register.GenDocsToFile(def, outPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated %s\n", outPath)
	}
}
