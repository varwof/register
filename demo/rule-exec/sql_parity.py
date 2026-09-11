#!/usr/bin/env python3
"""SQL 一致性 runner：执行 ruleexec 生成的 SQL（MySQL 方言）在 SQLite 上的等价形式，
并核对结果是否与向量中的 expect_ids 一致。

用法:
    python3 sql_parity.py [向量文件路径]

依赖：仅 Python 标准库（sqlite3）。
方言适配（仅用于测试，不改变被测 SQL 的语义）：
    BINARY `col`  →  `col` COLLATE BINARY     （SQLite 不支持 MySQL 的 BINARY 前缀）
    `col`         →  "col"                     （反引号在 SQLite 也可用，此处保持原样）
"""
import json
import re
import sqlite3
import sys
from pathlib import Path

DEFAULT = Path(__file__).resolve().parents[2] / "ruleexec" / "testdata" / "sql-parity-vectors.json"


def to_sqlite(sql: str) -> str:
    # MySQL: BINARY `col` = ...   →   SQLite: `col` COLLATE BINARY = ...
    return re.sub(r"BINARY\s+(`[^`]+`)", r"\1 COLLATE BINARY", sql)


def run_case(case: dict) -> tuple[bool, str]:
    con = sqlite3.connect(":memory:")
    try:
        con.execute(case["schema"])
        placeholders = ",".join("?" * len(case["rows"][0]))
        con.executemany(f"INSERT INTO {case['schema'].split()[2]} VALUES ({placeholders})", case["rows"])
        cur = con.execute(to_sqlite(case["sql"]), case.get("args", []))
        got = sorted(int(r[0]) for r in cur.fetchall())
        want = sorted(case["expect_ids"])
        return got == want, f"got={got} want={want}"
    finally:
        con.close()


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    cases = json.loads(path.read_text(encoding="utf-8"))["cases"]
    failed = 0
    for case in cases:
        ok, detail = run_case(case)
        print(f"{'PASS' if ok else 'FAIL'}  {case['id']:<20} {detail}  // {case['derivation']}")
        failed += 0 if ok else 1
    print(f"\nTotal: {len(cases)} | Pass: {len(cases) - failed} | Fail: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
