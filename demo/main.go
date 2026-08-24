// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/varwof/register"
)

func main() {
	usage := func() {
		fmt.Println("Usage: capability-demo -data <capability-data-dir> <command> [args]")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  list                                    列出所有已注册的能力")
		fmt.Println("  get <vendor/product>                    查看某个产品的所有能力")
		fmt.Println("  validate <vendor/product:capability>    验证单个能力")
		fmt.Println("  check <cap1> <cap2> ...                 批量验证能力")
		fmt.Println("  subset <declared> <allowed>             检查子集关系")
		fmt.Println("  search <keyword>                        搜索能力")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  capability-demo -data ../capability/data get oracle/mysql")
		fmt.Println("  capability-demo -data ../capability/data validate oracle/mysql:query:users")
		fmt.Println("  capability-demo -data ../capability/data check oracle/mysql:query:users varwof/core:cert:issue")
		fmt.Println("  capability-demo -data ../capability/data search query")
	}

	if len(os.Args) < 2 {
		usage()
		return
	}

	dir := os.Getenv("CAPABILITY_DIR")
	if len(os.Args) >= 3 && os.Args[1] == "-data" {
		dir = os.Args[2]
		os.Args = append(os.Args[:1], os.Args[3:]...)
	}
	if dir == "" {
		fmt.Fprintln(os.Stderr, "Error: capability data directory required (-data flag or CAPABILITY_DIR env)")
		os.Exit(2)
	}
	reg, err := register.NewRegistryFromDisk(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading schemes from %s: %v\n", dir, err)
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "list":
		fmt.Print(reg.Summary())
		fmt.Println()
		for _, id := range reg.SchemeIDs() {
			def, _ := reg.Get(id)
			caps := register.ListCapabilities(def)
			fmt.Printf("[%s]\n", id)
			for _, c := range caps {
				fmt.Printf("  %s:%s\n", id, c)
			}
			fmt.Println()
		}

	case "get":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: capability-demo get <scheme>")
			os.Exit(1)
		}
		schemeID := os.Args[2]
		def, ok := reg.Get(schemeID)
		if !ok {
			fmt.Fprintf(os.Stderr, "Unknown scheme: %s\n", schemeID)
			os.Exit(1)
		}
		fmt.Printf("Scheme: %s (%s) v%s\n", def.Name, def.SchemeID, def.Version)
		fmt.Printf("Description: %s\n", def.Description)
		fmt.Println()
		for _, c := range def.Capabilities {
			fmt.Printf("  %s:%s\n", def.SchemeID, c.ID)
			fmt.Printf("    %s\n", c.Description)
			if len(c.Parameters) > 0 {
				fmt.Println("    Parameters:")
				for name, p := range c.Parameters {
					fmt.Printf("      %s (%s) — %s\n", name, p.Type, p.Description)
					if p.Default != nil {
						fmt.Printf("        default: %v\n", p.Default)
					}
					if p.Required {
						fmt.Printf("        required: true\n")
					}
				}
			}
			fmt.Println()
		}

	case "validate":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: capability-demo validate <scheme:capability>")
			os.Exit(1)
		}
		cap := os.Args[2]
		def, entry, err := reg.ValidateCapability(cap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("VALID: %s:%s\n", def.SchemeID, entry.ID)
		fmt.Printf("  Scheme: %s (%s)\n", def.Name, def.Version)
		fmt.Printf("  Description: %s\n", entry.Description)
		if len(entry.Parameters) > 0 {
			fmt.Println("  Parameters:")
			for name, p := range entry.Parameters {
				req := ""
				if p.Required {
					req = " [required]"
				}
				fmt.Printf("    %s (%s)%s\n", name, p.Type, req)
			}
		}

	case "check":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: capability-demo check <cap1> <cap2> ...")
			os.Exit(1)
		}
		caps := os.Args[2:]
		result := reg.ValidateCapabilities(caps)
		for _, e := range result.Errors {
			fmt.Fprintf(os.Stderr, "  INVALID: %s — %s\n", e.Field, e.Message)
		}
		if result.Valid {
			fmt.Printf("All %d capabilities are valid\n", result.Checked)
		} else {
			fmt.Fprintf(os.Stderr, "%d/%d capabilities invalid\n",
				len(result.Errors), result.Checked)
			os.Exit(1)
		}

	case "subset":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Usage: capability-demo subset <declared_caps> <allowed_caps>")
			fmt.Fprintln(os.Stderr, "  e.g.: capability-demo subset 'oracle/mysql:query:users,oracle/mysql:write:orders' 'oracle/mysql:query:users'")
			os.Exit(1)
		}
		declared := strings.Split(os.Args[2], ",")
		allowed := strings.Split(os.Args[3], ",")
		denied := reg.CheckSubset(declared, allowed)
		if len(denied) == 0 {
			fmt.Printf("Subset check PASSED: all %d declared capabilities are allowed\n", len(declared))
		} else {
			fmt.Printf("Subset check FAILED: %d capabilities denied\n", len(denied))
			for _, d := range denied {
				fmt.Printf("  DENIED: %s\n", d)
			}
			os.Exit(1)
		}

	case "search":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: capability-demo search <keyword>")
			os.Exit(1)
		}
		keyword := strings.ToLower(os.Args[2])
		found := false
		for _, id := range reg.SchemeIDs() {
			def, _ := reg.Get(id)
			for _, c := range def.Capabilities {
				full := def.SchemeID + ":" + c.ID
				if strings.Contains(strings.ToLower(full), keyword) ||
					strings.Contains(strings.ToLower(c.Description), keyword) {
					fmt.Printf("  %s — %s\n", full, c.Description)
					found = true
				}
			}
		}
		if !found {
			fmt.Println("No capabilities found matching:", keyword)
		}

	default:
		usage()
		os.Exit(1)
	}
}
