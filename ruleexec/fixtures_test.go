// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"fmt"
	"path/filepath"

	"github.com/varwof/register"
)

// ruleJSON is the canonical demo rule used across ruleexec tests.
const ruleJSON = `{
  "rule_id": "org-a-db-readonly-2026",
  "version": "1.0.0",
  "scheme": "std/database-v1",
  "capability": "query:SELECT",
  "params": {
    "tables": ["customers"],
    "columns": { "customers": ["id", "name"] },
    "filter_columns": { "customers": ["tenant_id"] },
    "row_filter": {
      "customers": { "and": [ { "column": "tenant_id", "op": "=", "value": "org-a" } ] }
    },
    "limit": { "max": 100 }
  },
  "conditions": {
    "op": "and",
    "items": [
      { "op": "eq", "path": "request.tenant_id", "value": "org-a" },
      { "op": "lte", "path": "request.params.amount", "value": 1000 }
    ]
  },
  "constraints": [
    { "scheme": "varwof/constraint-v1", "id": "allowed-cidr", "params": ["10.0.0.0/8"] }
  ],
  "flow": {
    "steps": [
      { "name": "query", "kind": "op", "op": "db:select" },
      { "kind": "if", "condition": { "op": "gt", "path": "rowCount", "value": 0 },
        "then": [ { "name": "mark", "kind": "op", "op": "db:update" } ] },
      { "name": "notify", "kind": "op", "op": "db:notify" }
    ]
  }
}`

// demoRegistry provides the std/database-v1 scheme for rule validation.
//
// It loads the repository fixture rather than registering a stub with ids only:
// a stub declares no parameter contract, so parameter validation against it
// either rejects everything or (as it used to) silently accepts anything.
// Rule.Validate now enforces the registry's parameter contract, which is the
// same one the claims path uses.
func demoRegistry() *register.Registry {
	reg, err := register.NewRegistryFromDisk(filepath.Join("..", "testdata", "capability"))
	if err != nil {
		panic("ruleexec test fixture: " + err.Error())
	}
	return reg
}

// demoHandler mimics the mysql-api backend operations.
func demoHandler(op string, vars, req map[string]any) (map[string]any, error) {
	switch op {
	case "db:select":
		return map[string]any{"rowCount": 3}, nil
	case "db:update":
		if n, _ := vars["rowCount"].(int); n <= 0 {
			return nil, fmt.Errorf("no rows to update")
		}
		return map[string]any{"updated": true}, nil
	case "db:notify":
		return nil, nil
	}
	return nil, fmt.Errorf("unknown op %q", op)
}
