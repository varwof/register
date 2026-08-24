# Quick Start

Get started with Capability Register in 5 minutes.

## Scenario 1: Query Existing Capabilities

```go
package main

import (
    "fmt"
    "github.com/varwof/register"
)

func main() {
    reg, _ := register.NewRegistryWithEmbedded()

    // List all products
    fmt.Print(reg.Summary())

    // View all MySQL capabilities
    def, _ := reg.Get("oracle/mysql")
    for _, cap := range def.Capabilities {
        fmt.Printf("  %s:%s — %s\n", def.SchemeID, cap.ID, cap.Description)
    }
}
```

## Scenario 2: Validate Agent Capability Declarations

```go
// Capabilities declared by the Agent
agentCaps := []string{
    "oracle/mysql:query:users",
    "oracle/mysql:write:orders",
    "varwof/constraint-v1:time:window",
}

// Batch validation
result := reg.ValidateCapabilities(agentCaps)
if !result.Valid {
    for _, e := range result.Errors {
        fmt.Println("Rejected:", e)
    }
}
```

## Scenario 3: Permission Subset Check

```go
// Capabilities the Agent requests
declared := []string{
    "oracle/mysql:query:users",
    "oracle/mysql:write:orders",
    "oracle/mysql:delete:logs",
}

// Capabilities the user is authorized for
allowed := []string{
    "oracle/mysql:query:users",
    "oracle/mysql:query:orders",
}

// Check over-privilege
denied := reg.CheckSubset(declared, allowed)
if len(denied) > 0 {
    fmt.Println("Over-privileged capabilities:", denied)
    // Reject the Agent
}
```

## Scenario 4: Signature Verification

```bash
# Vendor signs capability.json
openssl pkcs7 -sign \
  -in varwof/core/v1.json \
  -out varwof/core/v1.json.p7s \
  -signer product.pem \
  -certfile chain.pem \
  -nodetach

# Verify the signature
openssl smime -verify \
  -in varwof/core/v1.json.p7s \
  -content varwof/core/v1.json \
  -CAfile pki/root-ca.pem
```

```go
// Go verification
trustRoots, _ := register.LoadTrustRoots("pki/")
err := register.VerifyCapabilityPKCS7("varwof/core/v1.json", trustRoots)
if err != nil {
    fmt.Println("Signature verification failed:", err)
}
```

## Scenario 5: Add Custom Capabilities

```bash
# 1. Create the directory
mkdir -p register/redis-ltd/redis

# 2. Create capability.json
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

# 3. Test
go run ./demo get redis-ltd/redis
go run ./demo validate redis-ltd/redis:get
```
