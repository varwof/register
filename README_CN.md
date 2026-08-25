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
go run ./cmd/gen-authz -list varwof/core/v1.json varwof/gateway/v1.json
go run ./cmd/gen-authz -out /tmp/authz.json varwof/core/v1.json varwof/gateway/v1.json
go run ./demo validate varwof/core:cert:issue
```

## 安装

```bash
go get github.com/varwof/register@v0.1.0
```

register 是 varwof 生态的**能力规范层**。本项目是 [Open Invention Network](https://openinventionnetwork.com/) 成员。

## 链接

| | |
|---|---|
| 主页 | https://varwof.com |
| 社区 | https://varwof.org |
| IETF 草案 | [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) |
| 许可证 | Apache-2.0 |
| 成员 | [Open Invention Network](https://openinventionnetwork.com/) |
