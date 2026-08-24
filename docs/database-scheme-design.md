# Database 能力方案设计探讨

> **状态：探索草稿，非规范**
> 日期：2026-08-23
> 关联：register 项目、AIC-JWT（draft-wei-aic-jwt-00）
> 目的：在定稿前对齐核心设计决策；本文档不承诺任何字段/文件为最终形式。

---

## 1. 背景与目标

以数据库为**标杆**，打造第一个"标准语义规范"：用表（对象级）、列（列级）、
行过滤 WHERE（行级）三层限定表达细粒度授权。任何数据库引擎只要按照该契约
对接（MySQL 查询改写 / PostgreSQL RLS 等适配器），即可复用同一套权限语义、
校验逻辑与审计口径。

验收标准：**极大缓解复杂度**——开发者不用为每个数据库/每个客户自造权限模型，
而是"一个标准契约 + 每库一个适配器"。

其他 scheme（HTTP API 等）按同一方法论开放合作，数据库先行。

## 2. 核心设计问题（7 问）

### Q1 公共标准命名空间（谁治理）

- 现状：register 强制 `vendor/product`（`varwof/core`、`oracle/mysql`）。
- 选项：
  a) 公共标准用 `std/<name>-v<major>`（中立命名空间，需治理流程）；
  b) 继续 `varwof/<name>-v<major>`（现实维护者 varwof）；
  c) 无前缀 `<name>-v<major>`（需改 `ValidateSchemeID`）。
- 推荐：**a**——"全球互通、保持开放"的前提是公共标准不被厂商前缀垄断。
- 开放问题：`std/` 命名空间的治理/审核/防抢注流程；是否需要代码层保留字校验。

### Q2 参数模型：扁平 vs 嵌套

- 现状：`ParameterDef` 仅支持扁平 `type/min/max/enum/default`，无法表达
  表、列、行过滤这类嵌套结构。
- 推荐：新增**可选** `params_schema`（JSON Schema）字段承载嵌套参数，
  扁平 `parameters` 保留做兼容；扩展需在 schema.go 增加一个
  `json.RawMessage` 字段（additive，不破坏现有数据）。
- 开放问题：是否允许两种模型混用；JSON Schema 方言版本（draft-07）。

### Q3 WHERE 限定文法（安全关键）

- 选项：
  a) **结构化谓词 AST**：`{column, op, value}` + `and/or/not`；
  b) 受限 SQL 片段。
- 推荐：**a**——只有结构化才能机械校验（过滤引用的列必须 ⊆ 列白名单）、
  防注入、可翻译到任意数据库。
- 开放问题：操作符集合（`=, !=, <, <=, >, >=, in, not in, between, like,
  is null, is not null`）；`like` 的通配限制（禁止裸前导通配）。

### Q4 行过滤"收窄"判定（最难，建议最先讨论）

- 语义：PA grant 给出行级上界，Agent 声明必须"更窄"（可加条件，不可放宽）。
- 选项：
  a) **语法级保守判定**：Agent 的 `and` 条件列表必须包含 grant 的全部条件
     （可离线、可验证、可复用 aic-jwt 已验证的 `ParamsWithinGrant` 思路）；
  b) 语义级判定：需要 DB schema 与真值语义，精确但复杂。
- 推荐：v1 用 **a**，语义级留作 v2 研究方向。
- 开放问题：grant 条件含 `or`/`not` 时保守判定是否过于严格；是否引入
  "条件归一化（CNF）"作为中间表示。

### Q5 校验位置（三层分工）

- 注册表：静态 schema 校验（能力合法、参数符合 schema；列必须真实存在 →
  需要与 `information_schema` 联动）。
- 网关运行时：P∩C 交集 + 收窄判定 + **迷你语言条件求值**（见 §4）。
- OPA：组织级动态策略（角色/OU、动态上下文），消费网关算好的事实。
- 原则：密码学与 AIC 语义在网关；组织策略在 OPA；词汇在注册表；不重复实现。

### Q6 版本策略

- 现状矛盾：README 的 `{vendor}/{product}/v{minor}.json` 与 architecture 的
  `{product}-v{major}` + 嵌套目录两套并存。
- 推荐：**大版本进 scheme_id**（`std/database-v1`），小版本为同目录
  `v{major}.{minor}.json`（如 `v1.0.json`、`v1.2.json`）；旧数据不动，文档统一。
- 配套：**default.json**（见 §3）。

### Q7 标杆 v1 范围

- 推荐：**最小闭环**——先只做 `query:SELECT`（单表 + 列白名单 + 行过滤 +
  limit + aggregate 开关），跑通"注册表定义 → PA 上界 → Agent 声明 →
  交集判定 → SQL 生成"全链路。
- INSERT/UPDATE/DELETE/DDL/TRUNCATE 作为后续迭代（UPDATE/DELETE 强制带
  行过滤，防全表改写）。

## 3. 版本与获取：default.json

目录示例：

```
data/std/database-v1/
├── v1.0.json      ← 初始小版本
├── v1.1.json      ← 新增能力/参数（向后兼容）
├── v1.2.json      ← 最新小版本
└── default.json   ← 与 v1.2.json 字节完全一致
```

- **default.json 是最高小版本的字节级副本**（非指针文件），保证 `.p7s`
  detached 签名原样有效，信任链零改动；
- 不参与 scheme 注册（文件名不以 `v` 开头，loader 现有过滤器天然跳过）；
- loader 新增 `LoadDefault(schemeID)`，消费方（网关、AI Agent、OPA bundle
  生成器）永远只认 `.../database-v1/default.json`；
- 发布工具（gen-authz 类）自动生成 default.json 副本并重签校验，防人工漂移；
- breaking change → 新大版本目录 `database-v2/`，自带自己的 default.json。

## 4. 运行时迷你语言

目标：网关执行侧可动态校验逻辑判断，**网关代码固定，逻辑存在于数据**
（grant/params 中的条件表达式）。

- 推荐：**结构化条件 AST**（JSON 操作符语言），与 row_filter 谓词同构：
  `and / or / not / eq / neq / lt / lte / gt / gte / in / contains / between /
  time-in / path（指向 request context 字段）/ value（字面量）`。
- 示例：

```json
"conditions": {
  "and": [
    { "op": "eq",      "path": "request.tenant_id", "value": "org-a" },
    { "op": "time-in", "path": "request.time",      "window": ["08:00", "22:00"] },
    { "op": "lte",     "path": "request.params.amount", "value": 1000 }
  ]
}
```

- 理由：天然安全（无字符串求值/注入）、可静态校验（JSON Schema 校验表达式）、
  Go 与 TS/浏览器各写一个 ~100 行求值器即可、与行过滤共享同一套文法与校验。
- 备选：CEL（Google 通用表达式语言，K8s/Envoy/OpenFGA 在用）——表达力强、
  Go 支持好，但浏览器端移植不成熟、对"最小语言"偏重。若未来需要复杂表达式，
  可将其作为可选扩展，OPA/Rego 已覆盖组织级复杂策略。
- 边界：核心操作符集合固定；新操作符走现有 `RegisterConstraint` 插件注册
  机制（固定核心 + 插件扩展）。

## 5. 已确认方向 / 未决清单

已确认（探索结论）：

- 三层限定：表 / 列 / 行过滤（WHERE）；
- WHERE 用结构化谓词 AST，禁止原始 SQL；
- 校验三层分工：注册表（schema）/ 网关（交集+收窄+条件求值）/ OPA（组织策略）；
- default.json 字节级副本作为稳定获取入口；
- 迷你语言用结构化条件 AST。

未决（待逐条对齐）：

- Q1：`std/` 公共命名空间的治理与是否加代码层保留字；
- Q2：是否给 schema.go 增加 `params_schema` 字段；
- Q4：收窄判定 v1 保守方案 vs 语义方案，以及 or/not 的处理；
- Q7：v1 最小闭环的具体范围与首版交付物（规范文档 / v1.json / 演示代码）。

## 7. 流程控制层（Mini Workflow，待定）

### 问题

条件语言（CEL / 结构化条件 AST）只回答"**某一步允不允许**"（布尔谓词），
表达不了"**任务按什么顺序、在什么条件下执行哪些步骤**"——即流程控制。
真实 Agent 任务是多步的：查询 → 判断结果 → 条件更新 → 重试 →
等待人工审批 → 补偿/回滚。

### 分层澄清（关键）

- **授权语言**（条件 AST / CEL）：每步操作执行前的权限检查，布尔，无流程；
- **流程语言**（Mini Workflow）：任务编排（状态机），每步执行前仍调用
  授权检查；
- 两者**不同层、不应合并**：把流程塞进 capability 会让 AIC 的授权语义越界；
  反过来，流程语言也不应承担授权判断。
- 对应 AIC-ROADMAP：流程语言属于 **Mission/Task 层**（MissionAuthorization，
  未来），与 AIC（身份/授权）分离——责任链
  Organization → Principal → Agent → **Mission/Task（流程）** → PEP。

### 流程控制：Python/C 风格子集（v1 草案）

目标：引入 Python/C 的基本流程控制（变量、条件、循环、函数），覆盖绝大多数
任务编排逻辑；**安全不靠"禁止循环"，而靠"执行预算沙箱"**（见下节）。

| 构造 | 说明 | 对应 Python/C |
|------|------|----------------|
| 变量与赋值 | 任务内局部变量，类型受限（string/int/float/bool/list/map） | `x = 1` |
| `if / else` | 条件分支，条件可用比较/逻辑 | `if x > 0:` |
| `while` | 条件循环 | `while cond:` |
| `for ... in range(...)` | 有界数值循环 | `for i in range(n):` |
| `for ... in list` | 遍历集合 | `for item in items:` |
| `break / continue` | 循环控制 | 同 Python |
| 函数/过程定义 | 复用逻辑，递归深度受预算限制 | `def f(x):` |
| 内建操作 | `retry`、`timeout/deadline`、`wait/gate`（人工审批）、`on-error` | 以库/操作形式提供 |

v2 候选：`parallel`、`compensate/rollback`（并行与补偿事务）。

### 形态选项

- a) **结构化流程 AST（JSON）**：与条件 AST 同风格，安全、可静态校验、
  Go/TS 可移植；
- b) **兼容开放标准子集**：CNCF **Serverless Workflow**（JSON/YAML，state:
  choice/parallel/map/wait/fail/succeed + retry/catch/timeouts）或
  AWS **Step Functions ASL**（StartAt/States/Choice/Fail/Succeed/Parallel/
  Map/Wait/Retry/Catch）；
- c) **Starlark（starlark-go）**：Python 语法子集 + 宿主强制步数/栈深度限制
  （Bazel 的构建语言，Go 实现成熟，确定性、无 I/O、无 eval）——
  **Go 网关的首选**；浏览器端需要 WASM 或改用 AST 子集。
- 推荐：**Go 网关用 Starlark，浏览器/纯 JSON 用结构化 AST 子集，二者语义
  对齐（共享测试向量）**；流程控制构造（if/while/for/break/def）两边一致，
  差异仅在语法（Python 风格文本 vs JSON）。

### 安全执行预算（沙箱，核心）

安全模型 = **执行预算 + 确定性 + 无副作用**，与 WASM gas / 以太坊 gas 同思路。
预算参数由规范统一定义默认值，实现不得自行放宽（防止"同一流程在不同网关
行为不同"）：

| 预算项 | 默认值 | 防什么 |
|--------|--------|--------|
| 总执行步数（每条语句/表达式计 1） | 10,000 | 无限循环、恶意长计算 |
| 总循环迭代数（所有循环**累计**） | 1,000 | **大批量循环**（不止单循环上限；正常任务编排几乎不会超过千次，超限视为异常） |
| 递归/调用深度 | 64 | 递归式死循环 |
| 语法嵌套深度 | 64 | 极端嵌套构造 |
| 集合元素总数上限 | 10,000 | 内存爆炸 |
| 墙钟超时（兜底） | 100 ms | 步数计数的实现偏差 |

DoS 防御要点（预算存在的根本理由）：

- 预算超限即**快速失败**，不等到资源耗尽再终止；
- 每次执行使用**独立预算**，互不共享、互不累积；
- **静态预检**：执行前直接拒绝明显超界的循环/重试（如 `for i in 0..1e9`），零运行时成本；
- 单次预算再小，也要配合**并发配额**（网关 max-concurrent）防并发洪泛；
- 规则文件受**签名保护**（未受信方无法注入规则），预算沙箱是第二道防线；
- 步数/迭代计数必须在解释器内层逐语句计数，不可被绕过；
- `budget_exceeded` 必须记审计，用于检测攻击模式。

其余硬规则：

- 确定性：无时间、无随机、无网络、无 I/O、无 eval、无文件、无宿主全局访问
  （变量只能来自显式绑定的任务上下文）；
- 禁止任意 goto / 自由跳转；
- **循环禁止嵌套**（结构约束，静态预检拒绝）：`while/for` 不得出现在另一
  循环体内（含经 if/retry/seq 传递）；允许 `if` 嵌套 `while`、`while` 嵌套
  `if`——从结构上消灭"迭代爆炸"这一类攻击；
- 预算超限 → 流程终止 + 明确错误码（如 `budget_exceeded`），**不留部分副作用**
  （按事务语义回滚已执行步骤）；
- 流程引擎与授权检查解耦：每步执行前做 AIC 条件检查，流程层不做授权。

### 开放问题

- 执行载体：**Starlark（Go 网关）vs 自研结构化 AST（浏览器）**——二者语义
  对齐的成本与测试向量如何共享；
- 预算默认值是否作为规范一部分写入注册表（倾向：**是**，随 scheme 定义发布）；
- 流程定义放哪：注册表（作为 scheme 的"流程型能力"？）还是部署侧
  （任务定义）——倾向**部署侧**，注册表只定义流程语法的 JSON Schema；
- 是否需要持久化/恢复（长任务中断续跑）——决定采用"状态机"还是简单线性脚本。

## 8. 端到端闭环：规则文件 → 签署 → 网关执行

### 流水线

```
① 编写规则文件（capability + params + conditions + flow + 角色/约束）
        │  gen-capability 校验（合法 / 冗余 / 越权）
        ▼
② 签署（PKCS#7 .p7s，组织私钥 / 规则发布者）
        │
        ▼
③ 分发（register 下载 / bundle 推送）
        │
        ▼
④ 网关执行：
     验签（规则签名 + 信任根）
     → schema 校验（能力/参数符合注册表定义，预算默认值来自规范）
     → P∩C 交集 + 收窄判定
     → 条件求值（迷你语言，执行预算沙箱）
     → 流程执行（Mini Workflow，预算沙箱）
     → 决策 + 审计
```

### 规则文件示例（草稿，非定稿）

```json
{
  "rule_id": "org-a-db-readonly-2026",
  "version": "1.0.0",
  "scheme": "std/database-v1",
  "grant": {
    "capability": "query:SELECT",
    "params": {
      "tables": ["customers"],
      "columns": { "customers": ["id", "name"] },
      "row_filter": {
        "customers": { "and": [ { "column": "tenant_id", "op": "=", "value": "org-a" } ] }
      },
      "limit": { "max": 100 }
    }
  },
  "conditions": {
    "op": "and",
    "items": [
      { "op": "eq",      "path": "request.tenant_id", "value": "org-a" },
      { "op": "time-in", "path": "request.time",      "window": ["08:00", "22:00"] }
    ]
  },
  "roles": ["readonly"],
  "constraints": [
    { "scheme": "varwof/constraint-v1", "id": "allowed-cidr", "params": ["10.0.0.0/8"] }
  ]
}
```

### 信任分层（谁签什么）

| 层 | 签署者 | 内容 |
|----|--------|------|
| 规范层 | register（能力注册中心） | capability 语义、参数 schema、预算默认值、流程语法 |
| 规则层 | 组织 / 规则发布者 | 谁对什么资源、什么边界（params + conditions + flow） |
| 授权层 | 责任主体（DA） | Agent 本次委托的授权证据（AIC 双层签名） |
| 执行层 | 网关 | 验全部签名后执行，审计 |

### 已具备 / 待建

已具备（现有代码）：

- register：capability.json + 命名/版本 + PKCS#7 签名/验签（sign.go/verify）、
  gen-authz / gen-docs / gen-capability、loader（嵌入+磁盘+热重载）；
- 网关运行时接线：core capregistry（签发侧校验）、gateway phase-one
  fail-closed（EffectiveCaps 未注册即拒）；
- aic-jwt：Go/TS 双层签名验证、P∩C、约束求值、能力匹配。

待建（按优先级）：

1. 规则文件格式定稿（rule.json 的 JSON Schema）；
2. 迷你语言运行时：条件求值器（Go Starlark / 浏览器 AST）+ 预算默认值规范；
3. Mini Workflow 流程引擎（线性脚本 → 状态机演进）；
4. 网关 rule loader：验签 + 热加载（复用现有 capreg 模式）；
5. 预算超限的事务性回滚语义。

### 开放问题（延续 §7）

- 规则文件与 PA grants 的关系：规则文件是 PA 的"可执行派生"还是独立实体；
- 规则由组织直接签署、还是经 register 背书后再下发；
- 流程定义是否允许嵌入规则文件（倾向：允许简单流程，复杂流程走部署侧任务定义）。

## 9.5 权威注册条目

`std/database-v1` 已固化为正式注册条目
（`register/data/std/database-v1/v1.json`）：7 个能力（query:SELECT/INSERT/
UPDATE/DELETE/EXECUTE、admin:DDL/TRUNCATE）+ 完整 params_schema（tables/
columns/filter_columns/row_filter/limit/aggregate + Filter 文法）+ 示例角色，
嵌入 loader 加载（`LoadEmbedded`）并参与 `ValidateCapability` 校验。

## 9.6 全球注册中心部署方案

见 `registry-deployment.md`（存档稿，状态：待仓库创建后执行）——GitHub PR 治理 +
Cloudflare Pages 静态分发 + PKCS#7 验签消费，实现全球开放能力注册中心。

## 9. 已落地（探索 demo：register/demo/rule-exec）

按 §8 闭环顺序实施的探索验证代码，全部可运行、可测试：

- ① **规则文件格式**：`rule.schema.json`（draft-07）+ `ValidateStructure`
  （条件 op / 流程 step kind / semver 结构校验）；
- ② **预算默认值随规范发布**：`budget-defaults.json`
  （steps 10k / iterations 1k / depth 64 / nesting 64 / wall_clock 100ms），
  `LoadBudgetDefaults` / `BudgetFromDefaults` 加载，实现不得放宽；
- ③ **迷你语言求值器（Go + TS 镜像）**：条件 AST 与流程引擎，
  预算沙箱 + 静态预检（循环禁止嵌套、超界拒绝），Go 与浏览器端
  语义一致、共享同一组测试场景；
- ④ **网关 phase-two 契约**：`PhaseTwo` 接口 + `RuleExecutor`
  （结构校验 → 静态预检 → 条件求值 → 流程执行），接在
  gateway-core `EffectiveCaps` 之后；
- **端到端闭环**：规则 → PKCS#7 签署 → 验签 → 执行 → 审计，
  `go run ./demo/rule-exec` 可完整复现；
- **MySQL 新版测试**：`sqlgen.go`（database-v1 契约 → MySQL SQL 翻译器，
  结构化谓词、防注入）+ 多用户权限矩阵测试（`mysql_test.go`）+
  `scripts/test/aic/aic-db-mysql-v2.sh` 编排脚本（含可选 MYSQL_DSN
  真实库断言 `TestMySQLLive`）；
- **HTTP 请求事实映射**：`request.go` 把 gateway-core `PluginContext`
  的 method/path/query/headers 映射为规则条件可用的
  `request.*` 字段（网关侧零侵入，字段为可选）；
- **规则发布**：`publish.go` + `-publish` 模式——按
  `rules/<vendor>/<product>-v<major>/vX.Y.json` 布局校验并 PKCS#7
  签署，自动生成 `default.json`（最高小版本字节副本，签名原样有效）
  与 manifest；
- **HTTP 网关整链路**：`httpgateway.go` 参考网关——请求 →
  phase-two 规则插件（HTTP 事实：method/path/query/headers）→
  生成 SQL → 真实 MySQL；`TestHTTPGatewayChain`（无库）与
  `TestHTTPGatewayE2ELive`（真实库，张三/李四列与租户隔离）双测；
- **可导入库包**：核心提炼为 `register/ruleexec`（可被网关等正式
  依赖）：规则模型/条件/流程/预算/SQL 生成/发布/网关插件适配器；
  `demo/rule-exec` 降为薄入口（演示与 `-sql`/`-publish` 工具）；
- **规则插件注册入口**：`ruleexec.LoadRulePlugin` /
  `RegisterRulePluginsFromDir` 从已发布目录（outDir/<scheme>/default.json
  + .p7s）验签后逐个注册 `RulePlugin`（每插件独立预算、验签强制、
  fail-closed；已注册 scheme 跳过，配置插件优先）；真实网关经
  `gateway/http.RegisterRulePlugins` 挂入 `PluginRegistry`；
- **网关配置项**：`rule_schemes` + `rule_signer_cert`（与
  `capability_schemes` 同风格的 opt-in 配置）——启动与 SIGHUP 重载时
  自动从发布目录加载签名规则并注册为能力插件；
- **真实网关整机 e2e**（`TestRealGatewayE2E`）：`varwof core init-full`
  建 PKI → `pki-client aic issue` 签发 AIC（能力
  `std/database-v1:query:SELECT`，capability_schemes 注册该 scheme、
  authz.json 加 db-reader 角色）→ 真实 HTTP 网关（mTLS + rule_schemes）
  → mysql-api → MariaDB；断言：GET employees 200、DELETE 403、
  orders 403；
- **一键 setup**：`scripts/test/aic/setup-e2e-pki.sh`——编译 core/client、
  init-full 建 PKI、修补 mTLS/能力注册表/authz 角色、后台起 serve、
  pki-client 签发矩阵用户（zhangsan/lisi/wangwu）的 AIC 证书，
  一键可复现整机 e2e 环境；
- **降权语义**（`TestPrincipalDowngradeRevokesAgentPermissions`）：
  CheckAdmission 在代表模式交集前，用主体**当前**证书（UserCert/
  凭证包，keyHash 校验同主体）的 PA 覆盖 P_grants——主体被吊销重签
  （同密钥、少权限）后，**旧 AIC 证书仍密码学有效，但越界能力从
  EffectiveCaps 消失**（权限收缩即时生效，无需重签 agent 证书）。
  吊销路径：core CLI `revoke` / API `POST /api/v1/cert/{ca}/{serial}/revoke`
  （支持按 PrincipalUid 级联）/ pki-client `revoke`；
- **真实网关权限矩阵**（`TestRealGatewayMatrixE2E`）：3 用户 × 4 方法
  （zhangsan GET / lisi GET+POST+PUT / wangwu 全量），网关经
  `CapabilityScheme`+`CapabilityPrefix` 做方法→必需能力映射，
  能力缺失即 403、命中即放行到 mysql-api——与 aic-matrix-demo 语义一致。

## 6. 相关现状

- register 已具备：capability.json + PKCS#7 签名 + gen-authz/gen-docs/
  gen-capability + 命名/版本工具链 + 网关运行时接线（core capregistry、
  gateway phase-one fail-closed）。
- register 目前为探索前原始状态（本文档不伴随任何代码改动）。
- 与 AIC-JWT 草案的关系：本方案的 capability 参数契约对应草案 §6 能力容器
  的 `params`；约束类型对应 §7；命名空间注册对应 §15 的外部能力方案注册表。
