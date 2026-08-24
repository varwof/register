# Capability Register (能力注册中心)

AI Agent 细粒度权限控制的标准能力定义注册中心。
能力规范以**可执行的 JSON 文件**（capability.json）为载体，支持 PKCS#7 签名，
并可从规范文件**生成 authz.json 授权策略**（gen-authz 工具）。

## 设计理念

```
产品方注册能力              Agent 查询能力
┌──────────────┐          ┌──────────┐
│ varwof/core  │          │ Agent A  │
│ core:        │◄────────►│ 持有 AIC │
│  cert:issue  │          │ 声明能力 │
│  ca:list     │          └──────────┘
└──────────────┘
     全球统一规则：同一产品，同一能力定义
     单一来源：capability.json → gen-authz → authz.json
```

## scheme_id 命名规范

| 类型 | 格式 | 示例 |
|------|------|------|
| **公共标准** | `<vendor>/<product>` | `varwof/core`, `varwof/gateway`, `oracle/mysql` |
| **私有扩展** | `x-<vendor>/<product>` | `x-vendor/acme` |
| **系统约束** | `varwof/constraint-v1` | 固定，不可私有 |

- 目录布局：`<root>/<vendor>/<product>/v<version>.json`
- `x-` 前缀标识私有扩展，与 HTTP `X-` 头惯例一致
- 能力完整标识：`vendor/product:capability_id`（如 `varwof/core:cert:issue`）

## 目录结构

```
register/
├── schema.go              # 能力定义结构体（SchemeDefinition/CapabilityEntry/RoleDef）
├── registry.go            # 注册/查询/验证
├── validator.go           # 权限校验引擎（MatchCapability/ValidateRoles）
├── genauthz.go            # authz.json 生成器（GenAuthz/GenAuthzToFile）
├── gendocs.go             # markdown 权限说明文档生成器（GenDocs）
├── mincap.go              # 最小权限校验器（合法/冗余/越权检测）
├── loader.go              # 嵌入式/磁盘加载器
├── sign.go                # PKCS#7 签名/验签
├── AI_PROMPT.md           # AI 最小权限 capability 生成 Prompt 模板
├── cmd/
│   ├── gen-authz/         # 从 capability.json 生成 authz.json 工具
│   ├── gen-docs/          # 从 capability.json 生成 markdown 权限说明
│   ├── gen-capability/    # 校验 AI 生成的能力集 + 最小权限建议
│   ├── sign/              # 签名 capability.json（.p7s）
│   └── verify/            # 验签 capability.json
├── demo/main.go           # 演示程序
├── docs/                  # 文档
│   ├── quickstart.md      # 快速入门
│   ├── reference.md       # API 参考
│   └── architecture.md    # 架构设计
│
├── varwof/
│   ├── core/              # varwof/core：PKI 核心权限（37 能力 + 10 角色）
│   ├── gateway/           # varwof/gateway：网关权限（21 能力 + 5 角色）
│   └── constraint/        # varwof/constraint-v1：系统约束
├── oracle/
│   └── mysql/             # oracle/mysql：MySQL 操作权限
└── x-vendor/
    └── acme/              # 私有扩展示例
```

## 快速开始

```bash
cd register

# 列出所有能力
go run ./cmd/gen-authz -list varwof/core/v1.json varwof/gateway/v1.json

# 查看某产品能力
go run ./demo get varwof/core

# 生成 authz.json（核心授权策略）
go run ./cmd/gen-authz -out /tmp/authz.json varwof/core/v1.json varwof/gateway/v1.json

# 验证单个能力
go run ./demo validate varwof/core:cert:issue

# 批量验证
go run ./demo check varwof/core:cert:issue varwof/gateway:proxy:http

# 检查子集关系
go run ./demo subset 'varwof/core:cert:issue,varwof/core:ca:list' 'varwof/core:cert:*'

# 搜索能力
go run ./demo search issue
```

## gen-authz：从规范生成授权策略

authz.json 是**派生产物**，由 capability.json（权威规范）生成，避免手工维护漂移。

```bash
# 生成 authz.json（角色 + OU 映射 + 网关命名空间 + 参数默认值）
go run ./cmd/gen-authz -out /tmp/authz.json \
    varwof/core/v1.json \
    varwof/gateway/v1.json

# 验签保护（capability.json 有 .p7s 时强制校验，缺失报错）
go run ./cmd/gen-authz -verify-required -trust-roots ca.pem \
    -out /tmp/authz.json varwof/core/v1.json

# 仅列出能力目录
go run ./cmd/gen-authz -list varwof/core/v1.json
```

### 映射规则

| capability.json | authz.json |
|---|---|
| 主方案 `roles`（如 varwof/core 的 admin/operator） | `roles` |
| 角色 `ous` | `ou_mapping` |
| 命名空间角色（`gateway:admin` 等，跨全部方案聚合） | `gateway_namespaces` |
| 能力 `parameters.default` | `capability_parameters`（`scheme:cap_id` → 默认值） |

### 校验

- 非通配 grant 必须被本方案 capabilities 覆盖（**错误**）
- 通配 grant（如 `gateway:*`）未命中本地时视为跨 scheme 命名空间授权（**警告**）
- 有 `.p7s` 签名时强制 PKCS#7 验签（`-verify-required`）

## gen-docs：从规范生成权限说明文档

每个 capability.json 可生成一份**人/AI 可读的 markdown 权限说明文档**，
完整描述每个能力的语义（何时需要/何时不应授予/示例/参数），作为 AI 生成
最小权限 capability 时的依据。

```bash
# 生成 varwof/core 与 varwof/gateway 的权限说明文档
go run ./cmd/gen-docs varwof/core/v1.json varwof/gateway/v1.json

# 目录模式：一次生成全部方案
go run ./cmd/gen-docs -all register/
```

生成的文档（`core-capabilities.md` / `gateway-capabilities.md`）包含：
能力目录表、能力详细语义、通配符与匹配规则、角色与授权映射、最小权限生成指南。

## AI 闭环：任务 → 最小权限 capability → 消费

**核心目标**：把 capability 规范（JSON + Markdown）交给 AI 大模型，
AI 根据任务自动生成**最小权限**的 capability 集合，从生成到消费完整闭环。

```
任务描述（如"为生产 HTTPS 服务签发证书"）
    │
    ▼
AI 大模型（读取 capability.json + capabilities.md + AI_PROMPT.md）
    │  判断任务类型、逐能力裁决、参数收窄
    ▼
最小权限 capability 集合（JSON claims）
    │
    ▼
gen-capability 校验器（合法性 + 冗余 + 越权检测）
    │
    ▼
最小权限集合 ──→ 签入 AIC/PA ──→ 网关消费（register 校验）
```

### 使用步骤

1. **准备材料**（已内置）：
   - `varwof/core/v1.json` + `varwof/core/core-capabilities.md`
   - `varwof/gateway/v1.json` + `varwof/gateway/gateway-capabilities.md`
   - `AI_PROMPT.md`（指导 AI 的完整 prompt 模板）

2. **AI 生成**：将上述材料 + 任务描述交给 AI，AI 输出 claims JSON 文件。

3. **机器校验**：

```bash
# 校验合法性（scheme/能力/参数）+ 冗余 + 越权检测
go run ./cmd/gen-capability -grants "cert:issue,ca:list,ca:info" claims.json

# 输出最小权限集合建议
go run ./cmd/gen-capability -grants "cert:issue,ca:list,ca:info" -minimal claims.json
```

4. **消费**：校验通过的最小权限集合签入 AIC/PA，网关在数据面据此鉴权。

### 校验能力

`gen-capability` 检测三类问题：

| 类别 | 说明 | 示例 |
|------|------|------|
| **非法声明** | scheme 未知 / 能力不存在 / 参数未定义 | `bogus/vendor:foo:bar` |
| **冗余声明** | 被通配覆盖或重复 | `ca:list` 被 `ca:*` 覆盖 |
| **越权能力** | 身份 grants 未授权 | `key:recover` 不在 grants 内 |

校验通过（`最小权限: true`）即可交付签入。

## 运行时接入（Phase D：register 权威 schema → 运行时校验）

能力规范闭环除生成派生产物外，还在运行时做**能力注册校验**（fail-closed）：
AIC 中声明的能力必须来自 register 方案，未注册的 scheme/capability 声明即拒绝。

### core（签发侧）

- 配置项 `capability_schemes`（空 = 嵌入式方案；指定目录 = 磁盘 override）
- 启动/`reloadConfigNowWithMuxes` 时 `loadCapRegistry` → `Server.SetCapRegistry`
- 签发 AIC / agent-proxy 证书时经 `SignConfig.ValidateCapabilities` 钩子校验全部能力
  （`internal/capregistry`，嵌入优先 + 磁盘覆盖 + 热重载原子替换）

### 三网关（数据面，opt-in）

- 配置项 `capability_schemes`（`gateway/http`、`gateway/tcp`、`gateway/udp`）
- **仅显式配置后启用**（向后兼容：默认不校验，旧 AIC 不受影响）
- `gateway/capreg.Loader` 统一加载（嵌入优先 + 磁盘覆盖），`NewGateway`/`Reload` 时
  注入 `gw.SetGlobalCapabilityRegistry`；`RunAccessPipeline` 阶段一校验
  EffectiveCaps 已注册，未注册 → 拒绝连接 + 审计
- 改磁盘方案 JSON → SIGHUP 热重载即时生效

## 如何注册新能力

### 公共标准

1. Fork 仓库
2. 在 `register/<vendor>/<product>/` 下创建目录（如 `varwof/core/`）
3. 添加 `v1.json`（参考下方格式，scheme_id 用 `<vendor>/<product>`）
4. 用 `go run ./cmd/sign` 签名生成 `.p7s`
5. 提交 PR，审核后发布

### 私有扩展

1. 在 `register/` 下创建 `x-<your-vendor>/` 目录
2. 添加 `v1.json`（scheme_id 用 `x-<your-vendor>/<product>`）
3. 可直接使用，无需审核

## capability.json 格式

```json
{
  "scheme_id": "varwof/core",
  "name": "Varwof PKI Core",
  "version": "1.1.0",
  "description": "Varwof PKI 核心引擎操作权限",
  "vendor": "varwof",
  "product": "core",
  "capabilities": [
    {
      "id": "cert:issue",
      "description": "签发证书",
      "parameters": {
        "max_validity_days": {
          "type": "int",
          "description": "最大有效期（天）",
          "default": 365,
          "min": 1,
          "max": 3650
        }
      }
    }
  ],
  "roles": {
    "admin": {
      "display_name": "管理员",
      "profiles": ["m-admin"],
      "ous": ["admin", "Admin"],
      "grants": ["ca:list", "cert:issue", "cert:revoke"]
    },
    "agent": {
      "display_name": "AI Agent",
      "profiles": ["agent-proxy"],
      "grants": ["gateway:*"]
    }
  }
}
```

## 字段说明

### SchemeDefinition

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| scheme_id | string | ✅ | 产品唯一标识（vendor/product） |
| name | string | ✅ | 产品名称 |
| version | string | ✅ | 语义化版本号 |
| description | string | ✅ | 产品描述 |
| vendor | string | ✅ | 厂商 |
| product | string | ✅ | 产品名 |
| author | string | | 作者 |
| license | string | | 许可证 |
| homepage | string | | 主页 |
| capabilities | []CapabilityEntry | ✅ | 能力列表 |
| roles | map[string]RoleDef | | 角色定义（gen-authz 用） |

### RoleDef

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| display_name | string | | 展示名 |
| profiles | []string | | 关联证书 profile |
| ous | []string | | 可绑定 OU（→ ou_mapping） |
| grants | []string | ✅ | 授权能力列表（支持通配，如 `ca:*`） |

### CapabilityEntry

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| id | string | ✅ | 能力 ID（domain:action，如 cert:issue） |
| description | string | ✅ | 能力描述 |
| parameters | map | | 参数定义（默认值→authz capability_parameters） |

### ParameterDef

| 字段 | 类型 | 说明 |
|------|------|------|
| type | string | 参数类型（int/string/bool/list） |
| description | string | 参数描述 |
| default | any | 默认值 |
| min | any | 最小值 |
| max | any | 最大值 |
| enum | []string | 枚举值 |
| required | bool | 是否必填 |

## 在 AIC 中使用

```go
// Agent 声明能力
capabilities := []pki.Capability{
    {SchemeId: "varwof/core", CapabilityId: "cert:issue"},
    {SchemeId: "varwof/gateway", CapabilityId: "proxy:http"},
    {SchemeId: "varwof/constraint-v1", CapabilityId: "time:window:0900-1800"},
}

// 网关验证
reg, _ := register.NewRegistryWithEmbedded()
for _, cap := range capabilities {
    full := cap.SchemeId + ":" + cap.CapabilityId
    if _, _, err := reg.ValidateCapability(full); err != nil {
        // 拒绝：未注册的能力
    }
}
```

## License

Apache-2.0
