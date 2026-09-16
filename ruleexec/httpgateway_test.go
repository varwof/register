// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	pki "github.com/varwof/types"
)

func zhangRuleJSON() string {
	return `{
		"rule_id": "zhang", "version": "1.0.0",
		"scheme": "std/database-v1", "capability": "query:SELECT",
		"params": {"tables": ["customers"], "columns": {"customers": ["id","name"]},
			"filter_columns": {"customers": ["tenant_id"]},
			"row_filter": {"customers": {"column": "tenant_id", "op": "=", "value": "org-a"}},
			"limit": {"max": 100}},
		"conditions": {"op": "and", "items": [
			{"op": "eq", "path": "request.method", "value": "GET"},
			{"op": "eq", "path": "request.query.tenant", "value": "org-a"}
		]}
	}`
}

func liRuleJSON() string {
	return `{
		"rule_id": "li", "version": "1.0.0",
		"scheme": "std/database-v1", "capability": "query:SELECT",
		"params": {"tables": ["customers"], "columns": {"customers": ["id","name","email"]},
			"filter_columns": {"customers": ["tenant_id"]},
			"row_filter": {"customers": {"column": "tenant_id", "op": "=", "value": "org-b"}},
			"limit": {"max": 50}},
		"conditions": {"op": "and", "items": [
			{"op": "eq", "path": "request.method", "value": "GET"},
			{"op": "eq", "path": "request.query.tenant", "value": "org-b"}
		]}
	}`
}

func newTestGateway(t *testing.T, exec SQLExecutor) (*HTTPGateway, map[string]*RulePlugin) {
	t.Helper()
	zhang, err := LoadRuleBytes([]byte(zhangRuleJSON()))
	if err != nil {
		t.Fatal(err)
	}
	li, err := LoadRuleBytes([]byte(liRuleJSON()))
	if err != nil {
		t.Fatal(err)
	}
	plugins := map[string]*RulePlugin{
		"zhangsan": NewRulePlugin("std/database-v1", zhang, NewBudget(), demoHandler),
		"lisi":     NewRulePlugin("std/database-v1", li, NewBudget(), demoHandler),
	}
	g := NewHTTPGateway(plugins, exec)
	// Tests have no TLS terminator, so model the mTLS layer the way a real
	// deployment provides it: an injected identity hook that returns the CN
	// from the request.  The gateway itself never reads X-Client-CN (audit
	// 2026-09-16, R7); this hook plays the position of the terminator that
	// would populate r.TLS.VerifiedChains.
	g.clientCN = func(r *http.Request) (string, bool) {
		cn := r.Header.Get("X-Client-CN")
		return cn, cn != ""
	}
	return g, plugins
}

// TestHTTPGatewayChain exercises the full "request -> rule plugin ->
// SQL" chain without a database (fake executor), asserting the auth
// and SQL-generation semantics.
// TestHTTPGatewayHeaderSpoofRefused pins audit R7: a client-supplied
// X-Client-CN header alone must NOT select a per-user rule — identity only
// comes from the verified mTLS peer cert (here: a gateway without an
// injected identity hook has no terminator, so it must fail closed).
func TestHTTPGatewayHeaderSpoofRefused(t *testing.T) {
	g, _ := newTestGateway(t, nil)
	// Remove the test identity hook so the production default applies:
	// only r.TLS.VerifiedChains counts.
	g.clientCN = g.clientCNFromMTLS
	req := httptest.NewRequest("GET", "/api/tables/customers/rows?tenant=org-a", nil)
	req.Header.Set("X-Client-CN", "zhangsan") // attacker-controlled
	rec := httptest.NewRecorder()
	g.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("spoofed header with no mTLS peer must be 401, got %d", rec.Code)
	}
}

func TestHTTPGatewayChain(t *testing.T) {
	var lastSQL string
	var lastArgs []any
	fake := func(ctx context.Context, q string, args ...any) ([]map[string]any, error) {
		lastSQL = q
		lastArgs = args
		return []map[string]any{{"id": 1, "name": "alice"}}, nil
	}
	g, _ := newTestGateway(t, fake)
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()

	get := func(cn, path string) *http.Response {
		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Client-CN", cn)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// 张三 -> allow, SQL filters org-a, no email
	resp := get("zhangsan", "/api/tables/customers/rows?tenant=org-a")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("zhang: status %d", resp.StatusCode)
	}
	if !strings.Contains(lastSQL, "`tenant_id` = ?") || strings.Contains(lastSQL, "`email`") {
		t.Fatalf("zhang SQL wrong: %s", lastSQL)
	}
	// The tenant value must travel as a bind parameter, never in the statement.
	if strings.Contains(lastSQL, "org-a") || len(lastArgs) != 1 || lastArgs[0] != "org-a" {
		t.Fatalf("zhang SQL/args wrong: sql=%s args=%v", lastSQL, lastArgs)
	}
	resp.Body.Close()

	// 李四 -> allow, SQL includes email and org-b
	resp = get("lisi", "/api/tables/customers/rows?tenant=org-b")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("li: status %d", resp.StatusCode)
	}
	if !strings.Contains(lastSQL, "`email`") || !strings.Contains(lastSQL, "`tenant_id` = ?") {
		t.Fatalf("li SQL wrong: %s", lastSQL)
	}
	if strings.Contains(lastSQL, "org-b") || len(lastArgs) != 1 || lastArgs[0] != "org-b" {
		t.Fatalf("li SQL/args wrong: sql=%s args=%v", lastSQL, lastArgs)
	}
	resp.Body.Close()

	// 张三 with wrong tenant -> deny (conditions)
	resp = get("zhangsan", "/api/tables/customers/rows?tenant=org-b")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong tenant: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	// unknown identity -> 401
	resp = get("mallory", "/api/tables/customers/rows?tenant=org-a")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown cn: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	// table not in rule -> deny
	resp = get("zhangsan", "/api/tables/orders/rows?tenant=org-a")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("table not in rule: status %d", resp.StatusCode)
	}
	resp.Body.Close()

	// POST -> deny (method condition)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/tables/customers/rows?tenant=org-a", nil)
	req.Header.Set("X-Client-CN", "zhangsan")
	postResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if postResp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST: status %d", postResp.StatusCode)
	}
	postResp.Body.Close()
}

// TestHTTPGatewayE2ELive runs the whole chain against a real
// MySQL/MariaDB (enable with MYSQL_DSN).
func TestHTTPGatewayE2ELive(t *testing.T) {
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		t.Skip("set MYSQL_DSN to run against a real MySQL/MariaDB")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	g, _ := newTestGateway(t, DBExecutor(db))
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()

	getBody := func(cn, path string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("X-Client-CN", cn)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(b)
	}

	code, body := getBody("zhangsan", "/api/tables/customers/rows?tenant=org-a")
	if code != http.StatusOK {
		t.Fatalf("zhang live: status %d body=%s", code, body)
	}
	var zhangResp struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal([]byte(body), &zhangResp); err != nil {
		t.Fatal(err)
	}
	if len(zhangResp.Rows) != 1 || zhangResp.Rows[0]["name"] != "alice" {
		t.Fatalf("zhang live rows wrong: %s", body)
	}
	if _, hasEmail := zhangResp.Rows[0]["email"]; hasEmail {
		t.Fatalf("zhang must not see email: %s", body)
	}

	code, body = getBody("lisi", "/api/tables/customers/rows?tenant=org-b")
	if code != http.StatusOK {
		t.Fatalf("li live: status %d body=%s", code, body)
	}
	var liResp struct {
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal([]byte(body), &liResp); err != nil {
		t.Fatal(err)
	}
	if len(liResp.Rows) != 1 || liResp.Rows[0]["name"] != "bob" {
		t.Fatalf("li live rows wrong: %s", body)
	}
	if _, hasEmail := liResp.Rows[0]["email"]; !hasEmail {
		t.Fatalf("li must see email: %s", body)
	}
}

var _ = fmt.Sprintf
var _ = pki.PluginAllow
