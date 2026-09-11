# 开发者文档

> English entry points: [README.md](../README.md), [docs/toolchain_EN.md](../docs/toolchain_EN.md), [docs/rule-authoring_EN.md](../docs/rule-authoring_EN.md).

## 目录结构

```
register/
├── schema.go          # 能力定义结构体
├── registry.go        # 注册/查询/验证
├── validator.go       # 权限校验引擎
├── mincap.go / flatparams.go / params_validate.go
├── genauthz.go / gendocs.go
├── loader.go          # 磁盘目录加载器（嵌入式已移除）
├── sign.go            # PKCS#7 签名/验证
│
├── semantics/         # 判定层 CLC-v1（文法/蕴含/交集/判定/规范码）
├── ruleexec/          # 执行层（规则/条件/流程/预算/SQL/发布/网关适配）
├── internal/rulesigner/  # 规则签名证书工具（demo 与测试用）
│
├── cmd/               # 见文末《命令行工具》表（7 个）
│                      # + vectors-run（CLC 一致性向量 runner）
├── demo/main.go       # 能力演示程序（-data <能力数据目录>）
├── demo/rule-exec/    # 规则执行端到端 demo + rule.schema.json + TS 镜像
├── testdata/          # 测试夹具（capability 数据）
│
├── docs/              # 用户文档
└── dev-docs/          # 开发者文档（本目录）
```

> 能力定义数据（`<vendor>/<product>/v*.json`）**不在本仓库**：已拆到独立的
> `capability` 模块，默认相对路径为 `../capability/data`。

## 开发指南

### 添加新产品

1. 在 `register/<vendor>/<product>/` 下创建 `v1.json`
2. 填写 capability.json（参考 schema.go 中的 SchemeDefinition）
3. 运行 `go run ./demo list` 验证
4. 提交 PR

### 修改现有能力

1. 编辑 `register/<vendor>/<product>/vN.json`
2. 版本号递增（v1.json → v2.json）
3. 保留旧版本（向后兼容）
4. 运行测试验证

### 签名流程

```bash
# 1. 生成产品密钥对
openssl ecparam -genkey -name prime256v1 -out product.key
openssl req -new -x509 -key product.key -out product.pem -days 365

# 2. 签署 capability.json
go run ./sign -cert product.pem -key product.key -in v1.json -out v1.json.p7s

# 3. 验证
go run ./verify -in v1.json -sig v1.json.p7s -CA pki/root-ca.pem
```

### 测试

```bash
# 运行所有测试
go test ./...

# 运行特定测试
go test -run TestValidate -v

# 构建验证
go build ./...
go vet ./...
```

### 能力数据来源（磁盘目录）

嵌入式加载已移除：`LoadEmbedded` / `NewRegistryWithEmbedded` 调用即报错，
能力数据一律从磁盘目录读取。

```go
reg, err := register.NewRegistryFromDisk("../capability/data")
```

命令行等价方式：

```bash
export CAPABILITY_DIR=../capability/data
go run ./demo -data $CAPABILITY_DIR list
```

loader 只接受 `v` 后跟数字开头的 JSON（`v1.json`、`v1.0.json`）作为方案定义；
`default.json`、`vectors.json` 等非方案文件会被跳过，`_` 开头的目录
（如 `_vectors/`）整个忽略。

## 代码规范

### 命名

- scheme_id: `vendor/product`（小写，连字符）
- capability_id: `category:action[:target]`（小写）
- 文件名: `v1.json`, `v2.json`（语义化版本）

### JSON 格式

- 2 空格缩进
- 字段顺序: scheme_id, name, version, description, vendor, product, ...
- 必填字段不可省略

### 提交规范

- feat: 新增能力定义
- fix: 修复能力定义
- docs: 更新文档
- refactor: 重构代码

## 命令行工具与流程

工具表、端到端流程图与门禁矩阵是**唯一一份**，在 [`../docs/toolchain.md`](../docs/toolchain.md)；
规则文件怎么写见 [`../docs/rule-authoring.md`](../docs/rule-authoring.md)。

## 判定层与执行层

一门语言两层，职责不重叠（详见 `docs/capability-language-layers.md`）：

| 层 | 包 | 职责 |
|----|----|------|
| 判定层 | `semantics/`（CLC-v1） | 能力文法、蕴含、参数域、交集、判定与规范码；纯函数、fail-closed |
| 执行层 | `ruleexec/` | 规则模型、运行上下文条件、`op \| if \| seq` 流程、预算、SQL、发布与验签 |

两条禁令：CLC 不得引入控制流；ruleexec 不得自行实现能力子集/deny 语义
（必须调用 CLC）。

条件语义与 SQL 映射见 `docs/condition-semantics.md`；执行语言刻意不含
循环、重试、`time-in`、`contains`。

## 相关项目

- `github.com/varwof/pkcs7` — PKCS#7 签名/验证
- `github.com/varwof/types` — AIC 类型定义
- `github.com/varwof/gateway-core` — 网关安全引擎
