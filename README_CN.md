# varwof-register

> 能力注册中心 —— AI Agent 细粒度权限控制的标准能力定义注册、验证与 authz.json 生成

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/register)](https://pkg.go.dev/github.com/varwof/register)

> ⚠️ **预览版** — 不可用于生产环境。API 和功能可能在正式发布前发生变更。

[English](README.md)

## 什么是 varwof-register？

AI Agent 细粒度权限控制的标准能力定义注册中心。能力规范以**可执行的 JSON 文件**（capability.json）为载体，支持 PKCS#7 签名，并可**生成 authz.json 授权策略**。

## 快速开始

```bash
cd register

# 能力数据在独立的 capability 模块里
export CAPABILITY_DIR=../capability/data

go run ./cmd/gen-authz -list $CAPABILITY_DIR/varwof/core/v1.json
go run ./cmd/gen-authz -out /tmp/authz.json $CAPABILITY_DIR/varwof/core/v1.json
go run ./demo -data $CAPABILITY_DIR validate varwof/core:cert:issue
```

## 安装

```bash
go get github.com/varwof/register@v0.1.0
```

register 是 varwof 生态的**能力规范层**。本项目是 [Open Invention Network](https://openinventionnetwork.com/) 成员。

## CLC-v1 语义实现（`semantics/`）与一致性 runner

`semantics/` 是 CLC-v1 的 Go 参考实现：`ValidateCapabilityID`（§3 文法）、
`Entails`（§6 授权绑定）、`Intersect`（§7 有效授权集）、`Authorize`（§9 判定函数）、
`CanonicalJSON`（JCS 规范化，用于摘要）。

所有失败均 fail-closed，并携带稳定错误码（§9.4）；多个条件同时失败时，按规范顺序
（§9.3）取唯一上报的码。

跑共享一致性向量（**verdict 与规范码 reason 双断言，任何不一致都会非零退出**）：

```bash
CLC_VECTORS=../capability/data/_vectors/clc-v1/vectors.json go run ./cmd/vectors-run/
```

CI（`.github/workflows/clc-conformance.yml`）会克隆 `varwof/capability`，在每次 push/PR
执行 `gofmt` / `go vet` / `go test` / 向量。

## 执行层（`ruleexec/`）

`ruleexec` 执行**签名规则**：`op | if | seq` 三种构造 + 运行上下文条件，固定预算
（步数 / 深度 / 嵌套），SQL 全量参数化。执行语言**没有循环、没有重试、没有
`time-in` 与 `contains`**——它们分别属于调用方/作业编排层和授权约束。

- [docs/capability-language-layers.md](docs/capability-language-layers.md) —— 一门语言两层、
  规则发布边界（`RuleWithinSignerGrant`）；
- [docs/condition-semantics.md](docs/condition-semantics.md) —— null / 类型 / 大小写 / SQL 映射
  规则与共享测试向量。

## 链接

| | |
|---|---|
| 主页 | https://varwof.com |
| 社区 | https://varwof.org |
| IETF 草案 | [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) |
| 许可证 | Apache-2.0 |
| 成员 | [Open Invention Network](https://openinventionnetwork.com/) |
