# Execution-side condition semantics (v1, finalised 2026-09-10)

Scope: `conditions` and `row_filter` in `ruleexec`.  One goal: **the same condition must
produce the same result whether it is evaluated in memory or in the database**, and that
must be mechanically verifiable.

> 中文版：[condition-semantics.md](condition-semantics.md)

## 1. Domains and truth values

- Conditions are **two-valued** (true / false); SQL's third value UNKNOWN is not imported.
- `null` is a **value**; a "missing path" is not a value, and for comparison operators it
  is an **error** (fail-closed).
- Types are strict: **no implicit conversion** (`"500"` ≠ `500`); integers and floats are
  normalised for numeric comparison.

## 2. Null rules (aligned with SQL)

| Rule | Statement | SQL equivalent |
|---|---|---|
| R1 | either side `null` in `eq/neq/lt/lte/gt/gte/between/in` → **false** | `col = NULL` / `col <> NULL` match no rows |
| R2 | the only way to test for null is `is-null` (a missing path also counts as "no value") | `IS NULL` / `IS NOT NULL` |
| R3 | an `in` list **must not contain null** (rejected at load time); a null left-hand value → false | `NULL IN (…)` is unknown |
| R4 | missing path with a comparison operator → **error** (not false) | a missing column is a SQL compile error |

## 3. Types and case

| Rule | Statement |
|---|---|
| R5 | numbers: `int` / `float` / `json.Number` compare after normalisation; no other type takes part in numeric comparison |
| R6 | strings: **byte-exact (case-sensitive)**; the SQL side forces `BINARY` for string comparison, matching in-memory behaviour |
| R7 | `between` bounds are declared as strings in the AST (`"1"`, `"1000"`) — this is the **only** place a string is parsed as a number |
| R8 | booleans, arrays, objects: value equality (arrays are order-sensitive; no set semantics) |

## 4. SQL mapping

Every value travels as a **bound parameter** (`?` + args) and is never concatenated into
the SQL text; only identifiers (table/column names) are back-quoted, and they come from
the rule's declared table/column allowlist.

| Condition | SQL | args |
|---|---|---|
| `eq(col, v)` (v not null) | `` BINARY `col` = ? `` (string) / `` `col` = ? `` | `[v]` |
| `eq(col, null)` | **rejected** (the generator errors: use `is null`) | — |
| `is-null(col)` | `` `col` IS NULL `` | `[]` |
| `not(is-null(col))` | `` `col` IS NOT NULL `` | `[]` |
| `in(col, [v1,v2])` | `` BINARY `col` IN (?, ?) `` (a list containing null → rejected) | `[v1, v2]` |
| `between(col, [lo,hi])` | `` `col` BETWEEN ? AND ? `` (null bound → rejected) | `[lo, hi]` |

## 5. Conformance checks (mechanically reproducible)

| Layer | Vectors | Consumers |
|---|---|---|
| in-memory truth table (null / missing / case / types) | `ruleexec/testdata/condition-vectors.json` (20 cases) | Go `TestConditionVectors` + TS `mini.test.ts` (**same file**) |
| SQL generation + database execution | `ruleexec/testdata/sql-parity-vectors.json` (4 cases) | Go `TestSQLParityVectors` (asserts the generated SQL) + `demo/rule-exec/sql_parity.py` (executes against SQLite and checks the row sets) |

```bash
go test ./ruleexec/ -run 'TestConditionVectors|TestSQLParityVectors'
python3 demo/rule-exec/sql_parity.py
node --disable-warning=ExperimentalWarning --experimental-strip-types --test demo/rule-exec/ts/mini.test.ts
```

## 6. Status and open items

- **SQL parameterisation: done (2026-09-10).**  `GenerateSelectSQL` returns
  `(sql, args, err)` and every value goes through a bound parameter; `SQLExecutor` was
  widened to `func(sql string, args ...any)` and `DBExecutor`, the HTTP gateway, the demo
  and all tests were updated together.  The injection test now asserts that the value
  appears in `args` and **not** in the SQL text.
- **Open:** a `ci` (case-insensitive) mode — if it is ever needed, it must be declared
  explicitly and use a collation consistent with the database; it must not rely on
  MySQL's default collation.
