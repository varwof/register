# 执行侧条件语义（v1，2026-09-10 定稿）

> English: [condition-semantics_EN.md](condition-semantics_EN.md)

适用范围：`ruleexec` 的 `conditions` 与 `row_filter`。目标只有一个：
**同一条件在内存判定与数据库判定上给出同一个结果**，并且可机械验证。

## 1. 值域与真值

- 条件是**二值**的（true / false），不引入 SQL 的三值 UNKNOWN；
- null 是一个**值**；"路径缺失"不是值，对比较类算子是**错误**（fail-closed）；
- 类型严格：**不做隐式类型转换**（`"500"` ≠ `500`）；整数与浮点在数值比较中归一。

## 2. null 规则（与 SQL 对齐）

| 规则 | 说明 | 对应 SQL |
|---|---|---|
| R1 | `eq/neq/lt/lte/gt/gte/between/in` 的任一端为 null → **false** | `col = NULL` / `col <> NULL` 均无行 |
| R2 | 唯一能测 null 的是 `is-null`（缺失路径同样算"无值"） | `IS NULL` / `IS NOT NULL` |
| R3 | `in` 列表**不得含 null**（加载期拒绝）；被比较值为 null → false | `NULL IN (...)` 为 unknown |
| R4 | 路径缺失 + 比较算子 → **error**（不是 false） | 列不存在是 SQL 编译错误 |

## 3. 类型与大小写

| 规则 | 说明 |
|---|---|
| R5 | 数值：`int` / `float` / `json.Number` 归一后比较；其它类型不参与数值比较 |
| R6 | 字符串：**字节精确（区分大小写）**；SQL 侧对字符串比较强制 `BINARY`，与内存一致 |
| R7 | `between` 的边界由 AST 声明为字符串（`"1"`、`"1000"`），**只有这里**允许把字符串解析成数字 |
| R8 | 布尔、数组、对象：按值相等（数组需同序；不做集合语义） |

## 4. SQL 映射表

所有值都以**绑定参数**（`?` + args）传递，绝不拼接进 SQL 文本；
只有标识符（表名/列名）以反引号引用，且来自规则声明的表/列白名单。

| 条件 | SQL | args |
|---|---|---|
| `eq(col, v)`（v 非 null） | `` BINARY `col` = ? ``（字符串）/ `` `col` = ? `` | `[v]` |
| `eq(col, null)` | **拒绝**（生成器报错：改用 `is null`） | — |
| `is-null(col)` | `` `col` IS NULL `` | `[]` |
| `not(is-null(col))` | `` `col` IS NOT NULL `` | `[]` |
| `in(col, [v1,v2])` | `` BINARY `col` IN (?, ?) ``（列表含 null → 拒绝） | `[v1, v2]` |
| `between(col, [lo,hi])` | `` `col` BETWEEN ? AND ? ``（含 null 边界 → 拒绝） | `[lo, hi]` |

## 5. 一致性验证（可机械复现）

| 层面 | 向量 | 消费者 |
|---|---|---|
| 内存条件真值表（null / 缺失 / 大小写 / 类型） | `ruleexec/testdata/condition-vectors.json`（20 条） | Go `TestConditionVectors` + TS `mini.test.ts`（同一文件） |
| SQL 生成 + 数据库执行 | `ruleexec/testdata/sql-parity-vectors.json`（4 条） | Go `TestSQLParityVectors`（断言生成的 SQL） + `demo/rule-exec/sql_parity.py`（SQLite 执行并核对行集） |

跑法：

```bash
go test ./ruleexec/ -run 'TestConditionVectors|TestSQLParityVectors'
python3 demo/rule-exec/sql_parity.py
node --disable-warning=ExperimentalWarning --experimental-strip-types --test demo/rule-exec/ts/mini.test.ts
```

## 6. 状态与遗留

- **SQL 参数化：已完成（2026-09-10）**。`GenerateSelectSQL` 返回 `(sql, args, err)`，
  值一律走绑定参数；`SQLExecutor` 已扩展为 `func(sql string, args ...any)`，
  `DBExecutor`、HTTP 网关、demo 与全部测试同步更新。
  注入测试现在断言"值出现在 args 里、且不出现在 SQL 文本中"。
- **遗留**：`ci`（不区分大小写）模式——如确有需求，必须显式声明并使用与数据库
  一致的 collation，不得依赖 MySQL 默认 collation。
