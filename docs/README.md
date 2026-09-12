# Capability Register — 用户文档

> English entry points: [../README.md](../README.md), [toolchain_EN.md](toolchain_EN.md), [rule-authoring_EN.md](rule-authoring_EN.md), [condition-semantics_EN.md](condition-semantics_EN.md).

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
    // 从磁盘能力数据目录加载（嵌入式加载已移除）
    reg, _ := register.NewRegistryFromDisk("../capability/data")

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
export CAPABILITY_DIR=../capability/data

# 列出所有能力
go run ./demo -data $CAPABILITY_DIR list

# 查看某个产品
go run ./demo -data $CAPABILITY_DIR get oracle/mysql

# 验证能力
go run ./demo -data $CAPABILITY_DIR validate oracle/mysql:query:users

# 批量验证
go run ./demo -data $CAPABILITY_DIR check oracle/mysql:query:users varwof/core-v1:cert:issue

# 搜索
go run ./demo -data $CAPABILITY_DIR search query
```

## 注册新能力

### 公共标准

1. Fork `varwof/capability` 仓库
2. 在 `data/<vendor>/<product>/` 下创建 `v1.json`
3. 提交 PR，审核后发布（本仓库只提供校验与生成工具）

### 私有扩展

1. 在 `data/x-<vendor>/<product>/` 下创建 `v1.json`
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
  -in ../capability/data/varwof/core-v1/v1.json.p7s \
  -content ../capability/data/varwof/core-v1/v1.json \
  -CAfile pki/register-sub-ca.pem
```

## API 参考

详见 [reference.md](reference.md)

## 架构设计

详见 [architecture.md](architecture.md)

## 相关文档

| 文档 | 内容 |
|------|------|
| [condition-semantics_EN.md](condition-semantics_EN.md) | 执行侧条件语义（英文版） |
| [condition-semantics.md](condition-semantics.md) | 执行侧条件语义（null / 类型 / 大小写 / SQL 映射 + 一致性向量） |
| [capability-language-layers.md](capability-language-layers.md) | 一门语言两层：CLC 判定 vs ruleexec 执行；发布边界与两条禁令 |
| [rule-authoring.md](rule-authoring.md) | **规则写入规范**：字段、封闭算子集、参数契约、门禁矩阵、失败即拒绝清单 |
| [toolchain.md](toolchain.md) | **工具链与端到端流程**：8 个工具的功能与用法、门禁矩阵、与设计原则的对应 |
| [rule-authoring_EN.md](rule-authoring_EN.md) / [toolchain_EN.md](toolchain_EN.md) | 上两份的英文版（对外引用请用这两份） |
| [database-scheme-design.md](database-scheme-design.md) | database-v1 能力方案与流程语言设计（含移除记录） |
| [reference.md](reference.md) / [architecture.md](architecture.md) | API 与架构参考 |
