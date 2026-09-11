# rule-exec — 规则层（执行侧）说明书

> English: [rule-authoring_EN.md](../../docs/rule-authoring_EN.md) (rule format) and [toolchain_EN.md](../../docs/toolchain_EN.md) (tools and flow).
> 本文件的中文内容与这两份英文文档一一对应。

> ⚠️ **探索态** — 规则格式尚未升格为随注册表发布的正式规范；本文档与
> `rule.schema.json`、`ruleexec.Rule` 三者必须一致（有测试守着）。

这一层回答一个问题：**谁在什么条件下、允许网关执行哪些操作**。
判定层（这份能力允许不允许）在 `semantics/`（CLC-v1），执行层只做两件事：
按规则检查运行上下文，然后按 `op | if | seq` 执行——**执行层不做授权判断**。

```
规则的来源            可验证的产物                加载与执行
────────────         ─────────────              ─────────────
rule.json      →  PKCS#7 签名 + default.json  →  验签 → 结构校验 →
（人或 AI 写）      + manifest.json               发布边界（签名者 AIC grant）→
                                                 条件求值 → op|if|seq → SQL
```

## 1. 规则文件格式

机器可读契约：[`rule.schema.json`](rule.schema.json)（draft-07，
`additionalProperties: false`）。字段与 `ruleexec.Rule` 逐字对应，
两者漂移会被 `TestRuleSchemaMatchesStruct` 拦下。

| 字段 | 必填 | 说明 |
|---|---|---|
| `rule_id` | ✅ | 1–128 字符 |
| `version` | ✅ | 语义化 `x.y.z` |
| `scheme` | ✅ | 能力方案，`vendor/product`，必须在注册表中存在 |
| `capability` | ✅ | 该方案下的能力 id |
| `params` | ✅ | 能力参数（受该方案的 params_schema 与 CLC-v1 §6.2 约束） |
| `conditions` | — | 运行上下文条件（结构化 AST，见 `../../docs/condition-semantics.md`） |
| `constraints` | — | 约束引用（`scheme` + `id` + `params`）；未知类型一律拒绝 |
| `flow` | — | `op` / `if` / `seq` 三种构造组成的有限树 |

条件算子仅限：`and / or / not / is-null / eq / neq / lt / lte / gt / gte / in / between`。
流程构造仅限：`op / if / seq`（**没有循环、没有重试**）。

## 2. 失败即拒绝（fail-closed）

| 情况 | 结果 |
|---|---|
| 出现未知/拼错的字段（如 `condtions`） | 拒绝加载（不允许静默丢约束） |
| PKCS#7 签名缺失、被改、不信任 | 拒绝加载 |
| 规则声明的能力**超出签名者自己 AIC grant** 的范围 | 拒绝加载（`RuleWithinSignerGrant`） |
| 规则声明的约束签名者没有 | 拒绝加载 |
| 未知 step kind / 条件算子 / 约束类型 | 拒绝加载 |
| 超过预算（步数 10k / 深度 64 / 嵌套 64） | 执行终止，明确错误码 |

## 3. 三步用法

```bash
# ① 规则文件：rules/<vendor>/<product>-v<major>/vX.Y.json
#    （见 /tmp/rules-src 示例；或用 rule.schema.json 让 AI 生成）

# ② 发布：结构校验 + PKCS#7 签名 + default.json（字节副本）+ manifest
go run ./demo/rule-exec -publish <rules-dir> -out <out-dir>
#    → <out-dir>/<scheme>/vX.Y.json(.p7s)、default.json(.p7s)、manifest（JSON 打到 stdout）

# ③ 加载并执行（进程内）
#    ruleexec.LoadRulePlugin(rulePath, trustRoots, handler)
#    ruleexec.RegisterRulePluginsFromDir(outDir, trustRoots, handler)

# 端到端演示（规则 → 签名 → 验签 → 条件 → 流程）
go run ./demo/rule-exec
```

## 4. 相关文档

- [`../../docs/condition-semantics.md`](../../docs/condition-semantics.md) —— 条件语义（null / 类型 / 大小写 / SQL 映射）与共享向量
- [`../../docs/capability-language-layers.md`](../../docs/capability-language-layers.md) —— 判定层与执行层的分工、规则发布边界
- [`../../docs/database-scheme-design.md`](../../docs/database-scheme-design.md) §8 —— 规则闭环与信任分层
