// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	pki "github.com/varwof/types"
)

// SQLExecutor runs a generated SQL statement and returns rows as JSON
// objects. The real implementation talks to MySQL; tests inject a fake.
type SQLExecutor func(sql string) ([]map[string]any, error)

// HTTPGateway is the reference "rule -> gateway -> mysql-api" chain: it
// simulates the gateway admission path (mTLS identity via X-Client-CN),
// runs the phase-two rule plugin, generates SQL from the rule params,
// and executes it against the database.
type HTTPGateway struct {
	plugins map[string]*RulePlugin // client CN -> per-user rule
	exec    SQLExecutor
	mux     *http.ServeMux
}

// NewHTTPGateway builds a gateway with per-user rules and an executor.
func NewHTTPGateway(plugins map[string]*RulePlugin, exec SQLExecutor) *HTTPGateway {
	g := &HTTPGateway{plugins: plugins, exec: exec, mux: http.NewServeMux()}
	// Method permission is decided by the rule conditions, not by the
	// router: all methods reach the plugin, which denies non-GET.
	g.mux.HandleFunc("/api/tables/{table}/rows", g.handleRows)
	g.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return g
}

// Handler exposes the HTTP handler (for httptest or a real server).
func (g *HTTPGateway) Handler() http.Handler { return g.mux }

func (g *HTTPGateway) handleRows(w http.ResponseWriter, r *http.Request) {
	cn := r.Header.Get("X-Client-CN")
	plugin := g.plugins[cn]
	if plugin == nil {
		httpError(w, http.StatusUnauthorized, "unknown client identity")
		return
	}
	rule := plugin.exec.Rule

	// HTTP request facts -> plugin context (the phase-two slot).
	ctx := &pki.PluginContext{
		ClientCN: cn,
		Method:   r.Method,
		Path:     r.URL.Path,
		Query:    r.URL.Query(),
		Headers:  headerMap(r.Header),
		Target:   "query:SELECT",
	}
	res, err := plugin.Execute(&pki.Capability{
		SchemeId:     "std/database-v1",
		CapabilityId: "query:SELECT",
	}, ctx)
	if err != nil {
		httpError(w, http.StatusBadGateway, fmt.Sprintf("rule error: %v", err))
		return
	}
	if res.Decision != pki.PluginAllow {
		httpError(w, http.StatusForbidden, res.Reason)
		return
	}

	// The requested table must be within the rule's tables (fail-closed).
	table := r.PathValue("table")
	if !ruleTables(rule).contains(table) {
		httpError(w, http.StatusForbidden, fmt.Sprintf("table %q not in rule", table))
		return
	}

	sqlStr, err := GenerateSelectSQL(rule.Params)
	if err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	rows, err := g.exec(sqlStr)
	if err != nil {
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sql": sqlStr, "rows": rows})
}

type stringSet map[string]struct{}

func (s stringSet) contains(v string) bool {
	_, ok := s[v]
	return ok
}

func ruleTables(rule *Rule) stringSet {
	var p struct {
		Tables []string `json:"tables"`
	}
	_ = json.Unmarshal(rule.Params, &p)
	out := stringSet{}
	for _, t := range p.Tables {
		out[t] = struct{}{}
	}
	return out
}

func headerMap(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// DBExecutor adapts a *sql.DB to SQLExecutor (real MySQL/MariaDB).
func DBExecutor(db *sql.DB) SQLExecutor {
	return func(q string) ([]map[string]any, error) {
		rows, err := db.Query(q)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		cols, err := rows.Columns()
		if err != nil {
			return nil, err
		}
		var out []map[string]any
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				return nil, err
			}
			row := make(map[string]any, len(cols))
			for i, c := range cols {
				switch v := vals[i].(type) {
				case []byte:
					row[c] = string(v)
				default:
					row[c] = v
				}
			}
			out = append(out, row)
		}
		return out, rows.Err()
	}
}
