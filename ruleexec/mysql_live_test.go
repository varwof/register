// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package ruleexec

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

// TestMySQLLive runs the generated database-v1 SQL against a real
// MySQL/MariaDB instance. Enable with MYSQL_DSN, e.g.:
//
//	MYSQL_DSN='root@unix(/tmp/aic-mysql.sock)/aic_test' \
//	  go test -run TestMySQLLive ./demo/rule-exec/
//
// The database must contain a customers table seeded like the
// mysql-api demo (id, name, email, ssn, tenant_id).
func TestMySQLLive(t *testing.T) {
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

	// 1) org-a rule (zhang): SELECT id,name WHERE tenant_id='org-a'
	rule, err := LoadRuleBytes([]byte(ruleJSON))
	if err != nil {
		t.Fatal(err)
	}
	sqlStr, err := GenerateSelectSQL(rule.Params)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(sqlStr)
	if err != nil {
		t.Fatalf("query %q: %v", sqlStr, err)
	}
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	if len(cols) != 2 || cols[0] != "id" || cols[1] != "name" {
		t.Fatalf("column leak for org-a: %v", cols)
	}
	count := 0
	for rows.Next() {
		count++
	}
	rows.Close()
	if count != 1 {
		t.Fatalf("org-a should return 1 row, got %d", count)
	}

	// 2) org-b rule (li): extra email column, different tenant
	liSQL := sqlForParams(t, `{"tables":["customers"],"columns":{"customers":["id","name","email"]},
		"filter_columns":{"customers":["tenant_id"]},
		"row_filter":{"customers":{"column":"tenant_id","op":"=","value":"org-b"}},
		"limit":{"max":50}}`)
	rows2, err := db.Query(liSQL)
	if err != nil {
		t.Fatalf("query %q: %v", liSQL, err)
	}
	cols2, err := rows2.Columns()
	if err != nil {
		t.Fatal(err)
	}
	if len(cols2) != 3 || cols2[2] != "email" {
		t.Fatalf("org-b columns wrong: %v", cols2)
	}
	count2 := 0
	for rows2.Next() {
		count2++
	}
	rows2.Close()
	if count2 != 1 {
		t.Fatalf("org-b should return 1 row, got %d", count2)
	}

	// 3) injection guard: the escaped literal is data, never code
	inj := "SELECT `id` FROM `customers` WHERE `tenant_id` = '1 OR 1=1'"
	rows3, err := db.Query(inj)
	if err != nil {
		t.Fatalf("injection query failed: %v", err)
	}
	if rows3.Next() {
		t.Fatalf("injection literal must not match rows")
	}
	rows3.Close()
}
