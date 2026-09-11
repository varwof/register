# 工具链与端到端流程

> English: [toolchain_EN.md](toolchain_EN.md)

本文档记录**从能力规范到可执行**的完整流程、每个工具的功能与用法，以及各道校验门在哪个环节生效。
规则文件自身的写法见 [`rule-authoring.md`](rule-authoring.md)；语义与分层见
[`capability-language-layers.md`](capability-language-layers.md)。

## 1. 端到端流程

```
① 能力规范（人写）
   capability.json（scheme / capabilities / params_schema / roles）
      ├─ cmd/sign  → .p7s        （签名）
      ├─ cmd/verify               （验签，失败非零退出）
      ├─ gen-docs → *-capabilities.md   （人/AI 可读语义，AI 的输入材料）
      └─ gen-backfill             （为 params_schema 挂 digest，防漂移）

② 需求 → 最小能力清单（AI）
   AI_PROMPT.md + 任务需求 → LLM → claims.json
      └─ gen-capability -schemes <data> [-minimal]
                                    （合法性 / 冗余 / 越权 + 参数契约；输出最小集合 JSON，含 scheme_version）

③ 签发（把清单嵌进身份）
   pki-client aic issue --from-claims claims.json
      → 派生 --caps（含 JSON 参数）、--pa 默认取同一集合（最小权限）
      → claims 文件摘要锚进签名 DA（服务端审计记录 claims=sha256:…）
      → 能力嵌进 AIC 扩展 / DA

④ 规则（执行侧策略）
   gen-rule -schemes <data> -claims claims.json -out rules/
      ├─ 结构 + 未知字段校验，参数契约校验（与 ② 同一份契约）
      └─ 可选 -template 带走 conditions / constraints / flow
   demo/rule-exec -publish rules/ -out published/
      → v<maj>.<min>.json(.p7s) + default.json(.p7s) + manifest.json

⑤ 加载与执行
   验签 → 结构校验 → 规则能力 ⊆ 签名者自己的 AIC grant → 条件求值 → op|if|seq → 参数化 SQL
```

关键点：**② 与 ④ 用的是同一份参数契约**（`registry.ValidateParams`），所以"签发给 AIC 的能力"和
"规则里声明的能力"不会各按一套标准；④ 与 ③ 之间没有人工搬运（`--from-claims` 直接吃 ② 的输出）。

## 2. 工具

| 工具 | 功能 | 用法 |
|---|---|---|
| `gen-authz` | capability 方案 → `authz.json`（roles / ou_mapping / gateway_namespaces / capability_parameters） | `go run ./cmd/gen-authz -out /tmp/authz.json <scheme.json> [...]`（`-list` 只列能力） |
| `gen-docs` | 方案 → markdown 权限说明（AI/人可读） | `go run ./cmd/gen-docs <scheme.json>`；`-all <data-dir>` 批量；`-out` 指定路径 |
| `gen-capability` | 校验 AI 能力声明（合法性/冗余/越权），输出最小权限集 | `go run ./cmd/gen-capability -schemes <data-dir> [-minimal] [-grants a,b] claims.json` |
| **`gen-rule`** | 从校验过的能力清单生成规则骨架；**两道门禁不过则不写任何文件** | `go run ./cmd/gen-rule -schemes <data-dir> -claims claims.json -out rules/ [-template t.json] [-version 1.0] [-force]` |
| `gen-backfill` | 为数据插入 `params_schema_digest`（已声明的校验漂移，不重复插入；其余字节原样） | `go run ./cmd/gen-backfill <data-dir>` |
| `sign` | PKCS#7 签署，产出 detached `.p7s` | `go run ./cmd/sign -cert c.pem -key k.pem -in v1.json [-out v1.json.p7s]` |
| `verify` | 校验签名链到信任根（失败非零退出） | `go run ./cmd/verify -in v1.json [-sig v1.json.p7s] -CA root.pem` |
| `vectors-run` | 跑 CLC-v1 一致性向量（verdict + 规范码 + 交集结果） | `CLC_VECTORS=<vectors.json> go run ./cmd/vectors-run/` |
| `demo/rule-exec` | 规则端到端演示；`-publish` 发布规则；`-sql` 只打印生成的 SQL | `go run ./demo/rule-exec [-publish rules/ -out published/]` |

除 `vectors-run`（纯 runner，用 `CLC_VECTORS` 指定输入）外，其余工具 `-h` 均打印用途与 flag。

## 3. 三个常用场景

```bash
# A. 只用能力规范
export CAPABILITY_DIR=../capability/data
go run ./demo -data $CAPABILITY_DIR list            # 列出全部能力
go run ./cmd/gen-docs -all $CAPABILITY_DIR           # 生成人/AI 可读文档

# B. 从需求到签发（AI 参与）
#    LLM 按 AI_PROMPT.md 产出 claims.json，先校验再签发
go run ./cmd/gen-capability -schemes $CAPABILITY_DIR -minimal claims.json > minimal.json
pki-client <cfg> aic issue --from-claims minimal.json --agent <id> --user-cert <c> --user-key <k>

# C. 从能力清单到可执行规则
go run ./cmd/gen-rule -schemes $CAPABILITY_DIR -claims minimal.json -out rules/
go run ./demo/rule-exec -publish rules/ -out published/
```

## 4. 门禁矩阵

| 环节 | 签名 | 结构 / 未知字段 | 参数契约（注册表） | 签名者 grant 边界 |
|---|---|---|---|---|
| `gen-capability`（claims） | — | — | ✅ | 越权检查（对给定 grants） |
| `gen-rule`（生成规则） | — | ✅ | ✅ | — |
| `rule-exec -publish` | ✅ 签 | ✅ | ✗ | ✗ |
| `LoadRulePlugin`（加载） | ✅ 验 | ✅ | ✗ | ✅ |
| `gen-backfill`（数据） | — | — | digest 漂移校验 | — |
| `vectors-run` / 属性测试 | — | — | CLC 语义一致性（76 向量 + 524 属性用例） | — |

**已知缺口**：参数契约目前只在生成路径（`gen-capability` / `gen-rule`）生效。手写的规则可以绕过它被签名并加载。
补齐方向：把注册表（或一个校验钩子）传进发布与加载路径。

## 5. 与设计原则的对应

判定层原则（P1–P12）见 capability 仓的
[`capability-language-core-principles-v1.md`](https://github.com/varwof/capability/blob/main/docs/capability-language-core-principles-v1.md)。
规则层与工具链沿用同一套纪律，落成这几条工程约束：

| # | 纪律 | 落点 |
|---|---|---|
| D1 | **一条契约，多处消费** | claims 与规则共用 `registry.ValidateParams`；规则文件形状由 schema 与结构体互相守着 |
| D2 | **fail-closed 默认** | 未知字段 / 未知参数 / 未知 step kind / 未知约束 / 超预算 一律拒绝 |
| D3 | **全有或全无** | `gen-rule` 任一 claim 不过则不写任何文件；发布前先校验全部版本 |
| D4 | **门禁必须覆盖所有入口** | 参数契约仅在生成路径生效 ⇒ 手写规则可绕过（当前缺口，见 §4） |
| D5 | **产物必须有门禁** | 生成物（`*-capabilities.md`、digest）若无 CI 校验就会漂移；要么加门禁，要么别提交 |

## 6. 一致性验证

```bash
# CLC 判定层（三个独立实现 + 属性测试：Go / Python / TypeScript）
CLC_VECTORS=../capability/data/_vectors/clc-v1/vectors.json go run ./cmd/vectors-run/
go test ./semantics/ -run TestIntersectionProperty -v
python3 ../aic-capability-demo/property_test.py

# 规则层
go test ./ruleexec/ ./cmd/gen-rule/ -v        # 规则校验、发布边界、参数契约守卫
go run ./demo/rule-exec                        # 规则 → 签名 → 校验 → 条件 → 流程
```

当前状态：CLC 向量 76/76（Go 与 Python）、P11 属性 524 例 0 失败、属性用例可复现（重生成字节一致）、
OCMP 离线向量 12 例覆盖 11/11 规范码、规则层测试全绿、TS 镜像 3/3、SQL parity 4/4。
