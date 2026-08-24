package ruleexec

import (
	"fmt"

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
      { "op": "time-in", "path": "request.time", "window": ["08:00", "22:00"] },
      { "op": "lte", "path": "request.params.amount", "value": 1000 }
    ]
  },
  "roles": ["readonly"],
  "constraints": [
    { "scheme": "varwof/constraint-v1", "id": "allowed-cidr", "params": ["10.0.0.0/8"] }
  ],
  "flow": {
    "steps": [
      { "name": "query", "kind": "op", "op": "db:select" },
      { "kind": "if", "condition": { "op": "gt", "path": "rowCount", "value": 0 },
        "then": [ { "name": "mark", "kind": "op", "op": "db:update" } ] },
      { "name": "notify", "kind": "retry", "max_retries": 2,
        "steps": [ { "kind": "op", "op": "db:notify" } ] }
    ]
  }
}`

// demoRegistry provides the std/database-v1 scheme for rule validation.
func demoRegistry() *register.Registry {
	reg := register.NewRegistry()
	reg.Register(&register.SchemeDefinition{
		SchemeID: "std/database-v1",
		Name:     "Standard Database Capabilities (v1)",
		Version:  "1.0.0",
		Vendor:   "std",
		Product:  "database-v1",
		Capabilities: []register.CapabilityEntry{
			{ID: "query:SELECT", Description: "read rows"},
			{ID: "query:UPDATE", Description: "update rows"},
		},
	})
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
