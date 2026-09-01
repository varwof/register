# Capability Register — 用户文档

## 概述

Capability Register 是 AI Agent 细粒度权限控制的标准能力定义注册中心。它定义了能力的格式、版本、验证规则，让不同产品基于统一标准构建 AIC 权限体系。

## 快速开始

### 安装

```bash
go get github.com/varwof/register
```

### 基本使用

```go
package main

import (
    "fmt"
    "github.com/varwof/register"
)

func main() {
    // 从嵌入式文件加载
    reg, _ := register.NewRegistryWithEmbedded()

    // 验证能力
    def, entry, err := reg.ValidateCapability("oracle/mysql:query:users")
    if err != nil {
        fmt.Println("能力未注册:", err)
        return
    }
    fmt.Printf("能力有效: %s — %s\n", def.Name, entry.Description)
}
```

### 命令行工具

```bash
cd register

# 列出所有能力
go run ./demo list

# 查看某个产品
go run ./demo get oracle/mysql

# 验证能力
go run ./demo validate oracle/mysql:query:users

# 批量验证
go run ./demo check oracle/mysql:query:users varwof/core:cert:issue

# 搜索
go run ./demo search query
```

## 注册新能力

### 公共标准

1. Fork 仓库
2. 在 `register/<vendor>/<product>/` 下创建 `v1.json`
3. 提交 PR，审核后发布

### 私有扩展

1. 在 `register/x-<vendor>/<product>/` 下创建 `v1.json`
2. 可直接使用，无需审核

## scheme_id 命名规范

| 类型 | 格式 | 示例 |
|------|------|------|
| 公共标准 | `<vendor>/<product>` | `oracle/mysql`, `varwof/core` |
| 私有扩展 | `x-<vendor>/<product>` | `x-acme/order` |

## 签名验证

规则文件通过 PKCS#7 签名提供完整性校验：

```bash
# 验证签名
openssl smime -verify \
  -in varwof/core/v1.json.p7s \
  -content varwof/core/v1.json \
  -CAfile pki/register-sub-ca.pem
```

## API 参考

详见 [reference.md](reference.md)

## 架构设计

详见 [architecture.md](architecture.md)
