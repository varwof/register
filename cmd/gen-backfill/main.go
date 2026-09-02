// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// gen-backfill fills params_schema_digest into capability data files.
//
// Usage: gen-backfill <capability-data-dir>
//
// For every vendor/product/v*.json under the directory, it inserts a
// params_schema_digest field right after each capability's params_schema,
// preserving all other bytes (key order, whitespace, omitempty zero-values)
// exactly. A file that already declares a digest is verified for drift instead
// of being modified.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/varwof/register"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: gen-backfill <capability-data-dir>\n\n")
		fmt.Fprintf(os.Stderr, "为 capability 数据文件按字节插入 params_schema_digest，其余内容原样保留。\n")
		fmt.Fprintf(os.Stderr, "已声明 digest 的文件先校验漂移，不重复插入。\n")
	}
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}
	root := args[0]

	rewritten := 0
	err := filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if !strings.HasPrefix(base, "v") || !strings.HasSuffix(base, ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		out, err := register.BackfillParamsSchemaDigests(data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if string(out) == string(data) {
			return nil // already up to date
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Printf("backfilled: %s\n", path)
		rewritten++
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("done: %d file(s) backfilled\n", rewritten)
}
