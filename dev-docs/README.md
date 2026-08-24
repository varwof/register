# 开发者文档

## 目录结构

```
register/
├── schema.go          # 能力定义结构体
├── registry.go        # 注册/查询/验证
├── validator.go       # 权限校验引擎
├── loader.go          # 嵌入式/磁盘加载器
├── sign.go            # PKCS#7 签名/验证
├── demo/main.go       # 演示程序
│
├── docs/              # 用户文档
├── dev-docs/          # 开发者文档（本目录）
│
├── varwof/            # 自有产品能力定义
├── oracle/            # 第三方产品
└── x-vendor/          # 私有扩展示例
```

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

### 嵌入式加载

新能力定义会自动通过 `go:embed` 嵌入二进制。更新 `loader.go` 中的 embed 指令：

```go
//go:embed varwof/core/*.json varwof/gateway/*.json varwof/constraint/*.json
//go:embed oracle/mysql/*.json
//go:embed x-vendor/acme/*.json
var embeddedSchemes embed.FS
```

添加新产品后，更新此指令。

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

## 相关项目

- `github.com/varwof/pkcs7` — PKCS#7 签名/验证
- `github.com/varwof/types` — AIC 类型定义
- `github.com/varwof/gateway-core` — 网关安全引擎
