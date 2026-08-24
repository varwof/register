package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/varwof/register"
)

func main() {
	var (
		out        = flag.String("out", "authz.json", "output authz.json path")
		version    = flag.String("version", "v2", "authz.json version field")
		verify     = flag.Bool("verify", false, "verify .p7s signature if present")
		requireSig = flag.Bool("verify-required", false, "fail if .p7s signature missing")
		trustRoots = flag.String("trust-roots", "", "comma-separated PEM trust root files for signature verification")
		nsPrefix   = flag.String("namespace-prefix", "gateway:", "gateway namespace prefix (default gateway:)")
		showCaps   = flag.Bool("list", false, "list capabilities of loaded schemes and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: gen-authz [flags] <main-scheme.json> [extra-scheme.json ...]\n\n")
		fmt.Fprintf(os.Stderr, "从 capability.json 方案生成 authz.json（角色→grants 授权策略）。\n\n")
		fmt.Fprintf(os.Stderr, "第一个参数是主方案（提供 roles），后续为能力目录补充方案。\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	cfg := register.GenAuthzConfig{
		SchemePaths:     args,
		VerifySignature: *verify,
		VerifyRequired:  *requireSig,
		Version:         *version,
		NamespacePrefix: *nsPrefix,
	}
	if *trustRoots != "" {
		cfg.TrustRootsPEM = strings.Split(*trustRoots, ",")
	}

	if *showCaps {
		for _, p := range args {
			def, err := register.LoadScheme(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error loading %s: %v\n", p, err)
				os.Exit(1)
			}
			fmt.Printf("== %s (v%s) — %d capabilities\n", def.SchemeID, def.Version, len(def.Capabilities))
			for _, c := range def.Capabilities {
				line := "  " + c.ID
				if c.Description != "" {
					line += " — " + c.Description
				}
				fmt.Println(line)
			}
		}
		return
	}

	if err := register.GenAuthzToFile(cfg, *out); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Generated %s from %s\n", *out, strings.Join(args, ", "))
}
