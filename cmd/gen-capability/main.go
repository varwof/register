// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/varwof/register"
)

func main() {
	var (
		granted   = flag.String("grants", "", "身份已拥有的 grants（逗号分隔，可含通配）；检测越权")
		schemeDir = flag.String("schemes", "", "capability 数据目录（data/ 下的 vendor/product/v*.json）")
		minimal   = flag.Bool("minimal", false, "输出最小权限集合（移除冗余 + 越权）")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: gen-capability -schemes <capability-data-dir> [flags] <claims.json>\n\n")
		fmt.Fprintf(os.Stderr, "校验 AI 生成的能力声明集合（合法性 + 冗余 + 越权），并输出最小权限建议。\n\n")
		fmt.Fprintf(os.Stderr, "claims.json 结构：[{\"scheme_id\":\"varwof/core\",\"capability\":\"cert:issue\",\"parameters\":{},\"rationale\":\"\"}]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}

	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", args[0], err)
		os.Exit(1)
	}
	claims, err := register.ParseCapabilityClaims(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing claims: %v\n", err)
		os.Exit(1)
	}

	if *schemeDir == "" {
		fmt.Fprintln(os.Stderr, "Error: -schemes required (capability data directory)")
		os.Exit(2)
	}
	schemes, err := register.LoadAllSchemes(*schemeDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading schemes: %v\n", err)
		os.Exit(1)
	}
	reg := register.NewRegistry()
	for _, def := range schemes {
		reg.Register(def)
	}

	var grantedPatterns []string
	if *granted != "" {
		grantedPatterns = strings.Split(*granted, ",")
		for i := range grantedPatterns {
			grantedPatterns[i] = strings.TrimSpace(grantedPatterns[i])
		}
	}

	rep := reg.CheckMinimalCapabilitySet(claims, grantedPatterns)

	// Report
	fmt.Printf("== 校验报告（共 %d 条声明）==\n", len(claims))
	if len(rep.InvalidClaims) > 0 {
		fmt.Printf("\n[非法声明 %d]\n", len(rep.InvalidClaims))
		for _, v := range rep.InvalidClaims {
			fmt.Printf("  - %s:%s — %s\n", v.Claim.SchemeID, v.Claim.Capability, v.Error)
		}
	}
	if len(rep.RedundantClaims) > 0 {
		fmt.Printf("\n[冗余声明 %d（建议移除）]\n", len(rep.RedundantClaims))
		for _, v := range rep.RedundantClaims {
			fmt.Printf("  - %s:%s — %s\n", v.Claim.SchemeID, v.Claim.Capability, v.Error)
		}
	}
	if len(rep.MissingGranted) > 0 {
		fmt.Printf("\n[越权能力 %d（身份未授权）]\n", len(rep.MissingGranted))
		for _, c := range rep.MissingGranted {
			fmt.Printf("  - %s\n", c)
		}
	}
	fmt.Printf("\n最小权限: %v\n", rep.IsMinimal)

	if *minimal {
		// Output minimal privilege set: valid + non-redundant + authorized
		grantedSet := make(map[string]bool)
		for _, g := range grantedPatterns {
			grantedSet[g] = true
		}
		minimalSet := make([]register.CapabilityClaim, 0, len(rep.ValidClaims))
		redundantKey := map[string]bool{}
		for _, r := range rep.RedundantClaims {
			redundantKey[r.Claim.SchemeID+":"+r.Claim.Capability] = true
		}
		missingKey := map[string]bool{}
		for _, c := range rep.MissingGranted {
			missingKey[c] = true
		}
		for _, v := range rep.ValidClaims {
			key := v.SchemeID + ":" + v.Capability
			if redundantKey[key] || missingKey[key] {
				continue
			}
			minimalSet = append(minimalSet, v)
		}
		out, err := json.MarshalIndent(minimalSet, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n== 最小权限集合 ==\n%s\n", out)
	}
}
