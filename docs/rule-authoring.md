# 规则写入规范（execution rule）

> English: [rule-authoring_EN.md](rule-authoring_EN.md)

> ⚠️ **探索态** — 规则格式尚未升格为随注册表发布的正式规范。本文档、`demo/rule-exec/rule.schema.json`
> 与 `ruleexec.Rule` 三者必须一致（有测试守着：`TestRuleSchemaMatchesStruct`）。

规则描述的是**网关在执行一个已授权操作时，还要满足什么运行条件、按什么步骤执行**。
它**不做授权判断**——授权属于判定层（CLC-v1 / AIC）。这条边界是硬性的：
`ruleexec` 不得自行实现能力子集或 deny 语义（见 `capability-language-layers.md`）。

## 1. 字段

机器可读契约：[`../demo/rule-exec/rule.schema.json`](../demo/rule-exec/rule.schema.json)（draft-07，`additionalProperties: false`）。

| 字段 | 必填 | 约束 |
|---|---|---|
| `rule_id` | ✅ | 1–128 字节，全局唯一（建议 `<scheme>-<capability>-v<maj>.<min>`） |
| `version` | ✅ | 语义化 `x.y.z` |
| `scheme` | ✅ | `vendor/product`，必须在注册表中存在 |
| `capability` | ✅ | 能力 id（不含 scheme），必须属于该 scheme |
| `params` | ✅ | JSON 对象；须满足**该能力的参数契约**（见 §5） |
| `conditions` | — | 运行上下文条件（结构化 AST，见 §3） |
| `constraints` | — | 约束引用数组（见 §4） |
| `flow` | — | `op` / `if` / `seq` 组成的有限树（见 §3） |

**未知字段一律拒绝**：加载器使用 `DisallowUnknownFields`，拼错的键（如 `condtions`）会让规则**加载失败**，
而不是静默丢掉一条约束。规则由机器生成的频率不低于人写，所以键名不允许宽容。

## 2. 最小示例

```json
{
  "rule_id": "org-a-db-readonly-2026",
  "version": "1.0.0",
  "scheme": "std/database-v1",
  "capability": "query:SELECT",
  "params": {
    "tables": ["customers"],
    "columns": { "customers": ["id", "name"] },
    "filter_columns": { "customers": ["tenant_id"] },
    "row_filter": { "customers": { "and": [ { "column": "tenant_id", "op": "=", "value": "org-a" } ] } },
    "limit": { "max": 100 }
  },
  "conditions": {
    "op": "and",
    "items": [ { "op": "eq", "path": "request.tenant_id", "value": "org-a" } ]
  },
  "constraints": [ { "scheme": "varwof/constraint-v1", "id": "allowed-cidr", "params": ["10.0.0.0/8"] } ],
  "flow": {
    "steps": [
      { "name": "query", "kind": "op", "op": "db:select" },
      { "kind": "if", "condition": { "op": "gt", "path": "rowCount", "value": 0 },
        "then": [ { "name": "mark", "kind": "op", "op": "db:update" } ] }
    ]
  }
}
```

## 3. 条件与流程：封闭算子集

**条件算子（12 个，封闭）**：`and` `or` `not` `is-null` `eq` `neq` `lt` `lte` `gt` `gte` `in` `between`。
形态：`{"op": ..., "path": ..., "value": ...|"window": [...]|"items": [...]}`。

语义要点（完整规则见 [`condition-semantics.md`](condition-semantics.md)）：

- 二值真值；比较类算子遇 `null`/缺失**恒为 false**，只有 `is-null` 能测"无值"；
- **不做隐式类型转换**：`"500"` ≠ `500`；字符串比较大小写敏感、按字节；
- 路径缺失 + 比较算子 = **错误**（不是 false）。

**流程构造（3 个，封闭）**：`op`（原子操作，输出并入任务变量）、`if`（分支）、`seq`（顺序）。
**没有循环、没有重试**——重试属于调用方/作业编排层，每次尝试重新过一遍授权。

**预算（随规范发布，不得放宽）**：步数 10,000 / 深度 64 / 嵌套 64（`demo/rule-exec/budget-defaults.json`）。超限即终止。

## 4. 约束（`constraints`）

形如 `{"scheme": "varwof/constraint-v1", "id": "<约束 id>", "params": [...]}`。
scheme 目前只允许 `varwof/constraint-v1`（含 `constraint` / `constraint-v1` 别名）；
**未知约束类型一律拒绝**（fail-closed）。

## 5. 参数契约（`params`）—— 与签发侧同一份契约

规则里的 `params` 必须满足**能力自己的参数契约**，这份契约由注册表提供，且**与签发给 AIC 的能力清单用的是同一个函数**
（`registry.ValidateParams`）：

1. 能力声明了 `params_schema` → 按该 schema 校验（`required`、类型、范围、`oneOf`…）；
2. 否则按扁平 `parameters` 契约校验（必填、类型、min/max/enum、未知键拒绝）。

参数契约**默认 fail-closed**：schema 声明了 `properties` 却没写 `additionalProperties` 时，视为**封闭对象**，
未声明的键（含拼错的键）一律拒绝。要允许自由键，必须在 schema 里显式写 `"additionalProperties": true` 或给子 schema。

> 这条曾经是两套实现：claims 路径用数据驱动 schema（查 `required`），规则路径用一份硬编码校验（不查 `required`，
> 且对其它 scheme 直接 `return nil`）。结果"签发给 AIC 的能力"和"规则里声明的能力"可以不一致。
> 现已统一为 `registry.ValidateParams`，两条路径共用。

## 6. 写入 → 校验 → 签名 → 加载

```bash
# ① 生成骨架（推荐：从校验过的最小能力清单，避免人工搬运参数）
go run ./cmd/gen-rule -schemes <capability-data-dir> -claims claims.json -out rules/
#    -template <rule.json>  带走 conditions / constraints / flow
#    -version 1.0           起始版本

# ② 手工/模板补充 conditions 与 flow（可选），然后发布：结构校验 + PKCS#7 签名
go run ./demo/rule-exec -publish rules/ -out published/
#    产物：<out>/<scheme>/v<maj>.<min>.json(.p7s) + default.json(.p7s) + manifest

# ③ 加载并执行（进程内）
#    ruleexec.LoadRulePlugin(rulePath, trustRoots, handler)
#    ruleexec.RegisterRulePluginsFromDir(outDir, trustRoots, handler)
```

## 7. 门禁矩阵（哪道门在哪个环节）

| 环节 | 签名 | 结构 / 未知字段 | 参数契约（注册表） | 签名者 grant 边界 |
|---|---|---|---|---|
| `gen-rule`（生成） | — | ✅ | ✅ | — |
| `-publish`（签名发布） | ✅ 签 | ✅ | ✗ | ✗ |
| `LoadRulePlugin`（加载） | ✅ 验 | ✅ | ✗ | ✅ |

**已知缺口**：参数契约目前只在**生成**路径上生效。手写或用其它方式生成的规则，可以不经参数契约就被签名、发布、加载。
（`loadAuthorizedRule` 没有 registry 参数，网关侧也未传。）补齐方式是把注册表（或一个校验钩子）传进发布/加载路径。

## 8. 失败即拒绝清单

| 情况 | 结果 |
|---|---|
| 未知/拼错字段 | 加载失败（不允许静默丢约束） |
| 未知 step kind / 条件算子 | 加载失败 |
| 未知约束 scheme | 校验失败 |
| 缺必填参数 / 未知参数 / 类型或范围不符 | 校验失败（生成与发布环节） |
| PKCS#7 缺失、被改、不信任 | 加载失败 |
| 规则能力超出**签名者自己的 AIC grant** | 加载失败（`RuleWithinSignerGrant`） |
| 超过预算 | 执行终止 + 明确错误码 |

## 9. 与能力清单的关系

规则与 AIC 里嵌的能力清单**描述同一件事的两半**：清单说"允许什么"，规则说"执行时还要满足什么"。
因此两者共用同一份参数契约（§5），并且规则在加载时还要证明它没超出签名者自己的授权（§8）。

当前模型限制：**每个 scheme 只注册一条规则**（插件持单个 `Rule`，发布目录里只有最高 minor 作为 `default.json` 被加载）。
需要多条策略时，拆成不同 scheme，或用模板把策略合并进一条规则——`gen-rule` 会在同 scheme 多规则时明确警告。
