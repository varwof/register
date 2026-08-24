# Capability Register — User Documentation

## Overview

Capability Register is a registry of standard capability definitions for fine-grained AI Agent permission control. It defines capability formats, versions, and validation rules, letting different products build AIC permission systems on a unified standard.

## Quick Start

### Installation

```bash
go get github.com/varwof/register
```

### Basic Usage

```go
package main

import (
    "fmt"
    "github.com/varwof/register"
)

func main() {
    // Load from embedded files
    reg, _ := register.NewRegistryWithEmbedded()

    // Validate a capability
    def, entry, err := reg.ValidateCapability("oracle/mysql:query:users")
    if err != nil {
        fmt.Println("Capability not registered:", err)
        return
    }
    fmt.Printf("Capability valid: %s — %s\n", def.Name, entry.Description)
}
```

### Command-Line Tools

```bash
cd register

# List all capabilities
go run ./demo list

# View a product
go run ./demo get oracle/mysql

# Validate a capability
go run ./demo validate oracle/mysql:query:users

# Batch validation
go run ./demo check oracle/mysql:query:users varwof/core:cert:issue

# Search
go run ./demo search query
```

## Registering New Capabilities

### Public Standard

1. Fork the repository
2. Create `v1.json` under `register/<vendor>/<product>/`
3. Submit a PR; published after review

### Private Extension

1. Create `v1.json` under `register/x-<vendor>/<product>/`
2. Usable directly, no review required

## scheme_id Naming Convention

| Type | Format | Example |
|------|--------|---------|
| Public standard | `<vendor>/<product>` | `oracle/mysql`, `varwof/core` |
| Private extension | `x-<vendor>/<product>` | `x-acme/order` |

## Signature Verification

Rule files are protected against tampering via PKCS#7 signatures:

```bash
# Verify the signature
openssl smime -verify \
  -in varwof/core/v1.json.p7s \
  -content varwof/core/v1.json \
  -CAfile pki/register-sub-ca.pem
```

## API Reference

See [reference.md](reference.md) for details.

## Architecture Design

See [architecture.md](architecture.md) for details.
