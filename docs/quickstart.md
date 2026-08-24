# Quick Start

5 分钟上手 Capability Register。

## 场景 1：查询已有能力

```go
package main

import (
    "fmt"
    "github.com/varwof/register"
)

func main() {
    reg, _ := register.NewRegistryWithEmbedded()

    // 列出所有产品
    fmt.Print(reg.Summary())

    // 查看 MySQL 的所有能力
    def, _ := reg.Get("oracle/mysql")
    for _, cap := range def.Capabilities {
        fmt.Printf("  %s:%s — %s\n", def.SchemeID, cap.ID, cap.Description)
    }
}
```

## 场景 2：验证 Agent 能力声明

```go
// Agent 声明的能力
agentCaps := []string{
    "oracle/mysql:query:users",
    "oracle/mysql:write:orders",
    "varwof/constraint-v1:time:window",
}

// 批量验证
result := reg.ValidateCapabilities(agentCaps)
if !result.Valid {
    for _, e := range result.Errors {
        fmt.Println("拒绝:", e)
    }
}
```

## 场景 3：权限子集检查

```go
// Agent 要求的能力
declared := []string{
    "oracle/mysql:query:users",
    "oracle/mysql:write:orders",
    "oracle/mysql:delete:logs",
}

// 用户授权的能力
allowed := []string{
    "oracle/mysql:query:users",
    "oracle/mysql:query:orders",
}

// 检查越权
denied := reg.CheckSubset(declared, allowed)
if len(denied) > 0 {
    fmt.Println("越权能力:", denied)
    // 拒绝 Agent
}
```

## 场景 4：签名验证

```bash
# 产品方签署 capability.json
openssl pkcs7 -sign \
  -in varwof/core/v1.json \
  -out varwof/core/v1.json.p7s \
  -signer product.pem \
  -certfile chain.pem \
  -nodetach

# 验证签名
openssl smime -verify \
  -in varwof/core/v1.json.p7s \
  -content varwof/core/v1.json \
  -CAfile pki/root-ca.pem
```

```go
// Go 验证
trustRoots, _ := register.LoadTrustRoots("pki/")
err := register.VerifyCapabilityPKCS7("varwof/core/v1.json", trustRoots)
if err != nil {
    fmt.Println("签名验证失败:", err)
}
```

## 场景 5：添加自定义能力

```bash
# 1. 创建目录
mkdir -p register/redis-ltd/redis

# 2. 创建 capability.json
cat > register/redis-ltd/redis/v1.json << 'EOF'
{
  "scheme_id": "redis-ltd/redis",
  "name": "Redis",
  "version": "1.0.0",
  "description": "Redis 缓存操作权限",
  "vendor": "redis-ltd",
  "product": "redis",
  "capabilities": [
    { "id": "get", "description": "读取缓存" },
    { "id": "set", "description": "写入缓存" },
    { "id": "del", "description": "删除缓存" }
  ]
}
EOF

# 3. 测试
go run ./demo get redis-ltd/redis
go run ./demo validate redis-ltd/redis:get
```
