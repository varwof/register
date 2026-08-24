# API Reference

## Schema

### SchemeID Format

格式：`{vendor}/{product}-v{major}`

- `varwof/demo-mysql-v1` — 大版本 1
- `varwof/demo-mysql-v2` — 大版本 2（breaking change）
- `oracle/mysql-v3` — 大版本 3

验证规则：
- vendor：小写字母 + 数字 + 连字符
- product：小写字母 + 数字 + 连字符 + `-v{N}` 后缀
- 必须包含 `/` 分隔 vendor 和 product

### SchemeDefinition

```go
type SchemeDefinition struct {
    SchemeID     string            `json:"scheme_id"`      // vendor/product
    Name         string            `json:"name"`
    Version      string            `json:"version"`        // semver
    Description  string            `json:"description"`
    Vendor       string            `json:"vendor"`
    Product      string            `json:"product"`
    Author       string            `json:"author,omitempty"`
    License      string            `json:"license,omitempty"`
    Homepage     string            `json:"homepage,omitempty"`
    Capabilities []CapabilityEntry `json:"capabilities"`
    Roles        map[string]RoleDef `json:"roles,omitempty"` // gen-authz 用
}
```

### RoleDef

```go
type RoleDef struct {
    DisplayName string   `json:"display_name,omitempty"`
    Profiles    []string `json:"profiles,omitempty"`
    Grants      []string `json:"grants"`
    OUs         []string `json:"ous,omitempty"`
}
```

角色定义：grants 引用本方案的 capability_id（支持通配如 `ca:*`），
OUs 在 gen-authz 时展开为 ou_mapping。

### CapabilityEntry

```go
type CapabilityEntry struct {
    ID          string                  `json:"id"`
    Description string                  `json:"description"`
    Parameters  map[string]ParameterDef `json:"parameters,omitempty"`
    // AI 友好的语义说明字段（gen-docs 生成权限文档用）
    Summary  string   `json:"summary,omitempty"`
    Usage    string   `json:"usage,omitempty"`    // 何时需要该能力
    WhenNot  string   `json:"when_not,omitempty"` // 何时不应授予
    Examples []string `json:"examples,omitempty"`
    Related  []string `json:"related,omitempty"`
}
```

### ParameterDef

```go
type ParameterDef struct {
    Type        string      `json:"type"`        // int/string/bool/list
    Description string      `json:"description,omitempty"`
    Default     interface{} `json:"default,omitempty"`
    Min         interface{} `json:"min,omitempty"`
    Max         interface{} `json:"max,omitempty"`
    Enum        []string    `json:"enum,omitempty"`
    Required    bool        `json:"required,omitempty"`
}
```

## Registry

### NewRegistry()

```go
func NewRegistry() *Registry
```

创建空注册中心。

### NewRegistryWithEmbedded()

```go
func NewRegistryWithEmbedded() (*Registry, error)
```

创建预加载嵌入式能力定义的注册中心。

### Register(def *SchemeDefinition)

```go
func (r *Registry) Register(def *SchemeDefinition)
```

注册一个能力定义。如果 scheme_id 已存在则覆盖。

### Get(schemeID string) (*SchemeDefinition, bool)

```go
func (r *Registry) Get(schemeID string) (*SchemeDefinition, bool)
```

按 scheme_id 获取能力定义。

### ValidateCapability(formatted string) (*SchemeDefinition, *CapabilityEntry, error)

```go
func (r *Registry) ValidateCapability(formatted string) (*SchemeDefinition, *CapabilityEntry, error)
```

验证 "vendor/product:capability_id" 格式的能力是否有效。

### ValidateCapabilities(caps []string) *ValidationResult

```go
func (r *Registry) ValidateCapabilities(caps []string) *ValidationResult
```

批量验证能力列表。

### CheckSubset(declared, allowed []string) []string

```go
func (r *Registry) CheckSubset(declared, allowed []string) []string
```

检查 declared 是否为 allowed 的子集。返回越权的能力。

### SchemeIDs() []string

```go
func (r *Registry) SchemeIDs() []string
```

返回所有已注册的 scheme_id，按字母排序。

### Summary() string

```go
func (r *Registry) Summary() string
```

返回人类可读的摘要。

## Loader

### LoadScheme(path string) (*SchemeDefinition, error)

```go
func LoadScheme(path string) (*SchemeDefinition, error)
```

从磁盘加载单个 capability JSON 文件。

### LoadFromDir(root string) (map[string]*SchemeDefinition, error)

```go
func LoadFromDir(root string) (map[string]*SchemeDefinition, error)
```

从目录树加载所有 capability JSON 文件。

### LoadEmbedded() (map[string]*SchemeDefinition, error)

```go
func LoadEmbedded() (map[string]*SchemeDefinition, error)
```

从嵌入式文件加载。

### LoadFromBoth(diskDir string) (map[string]*SchemeDefinition, error)

```go
func LoadFromBoth(diskDir string) (map[string]*SchemeDefinition, error)
```

嵌入式优先，磁盘覆盖。

## Signing

### SignCapability(certPath, keyPath, capPath, outputPath string) error

```go
func SignCapability(certPath, keyPath, capPath, outputPath string) error
```

用 PKCS#7 签署 capability JSON 文件。

### VerifyCapabilityPKCS7(capPath string, trustRoots []*x509.Certificate) error

```go
func VerifyCapabilityPKCS7(capPath string, trustRoots []*x509.Certificate) error
```

验证 .p7s 签名文件。

### LoadTrustRoots(path string) ([]*x509.Certificate, error)

```go
func LoadTrustRoots(path string) ([]*x509.Certificate, error)
```

从文件或目录加载信任根证书。

### LoadCertFile(path string) ([]*x509.Certificate, error)

```go
func LoadCertFile(path string) ([]*x509.Certificate, error)
```

读取 PEM 文件中的全部证书链（信任根/签名者链）。

## GenAuthz（从规范生成 authz.json）

### GenAuthz(cfg GenAuthzConfig) (*AuthzDocument, error)

```go
func GenAuthz(cfg GenAuthzConfig) (*AuthzDocument, error)
```

从 capability.json 方案生成 authz.json 文档。映射规则：
- 主方案（第一个）Roles → authz.json roles（grant 原样保留）
- 角色 OUs → ou_mapping
- 命名空间角色（如 gateway:admin，跨全部方案聚合）→ gateway_namespaces
- capability parameters.default → capability_parameters（`scheme:cap_id`）

### GenAuthzToFile(cfg GenAuthzConfig, outputPath string) error

```go
func GenAuthzToFile(cfg GenAuthzConfig, outputPath string) error
```

生成并写入 authz.json 文件。

### GenAuthzConfig

```go
type GenAuthzConfig struct {
    SchemePaths      []string // 第一个为主方案（提供 roles）
    VerifySignature  bool     // 有 .p7s 时验签
    VerifyRequired   bool     // 缺失 .p7s 直接报错
    TrustRootsPEM    []string // 验签信任根 PEM 文件
    Version          string   // authz.json version（默认 v2）
    NamespacePrefix  string   // 额外网关命名空间前缀（默认 gateway:）
}
```

### AuthzDocument

```go
type AuthzDocument struct {
    Version              string
    Roles                map[string]AuthzRoleDef
    OUMapping            map[string]string
    GatewayNamespaces    map[string]GatewayNSDef
    CapabilityParameters map[string]map[string]any // 参数默认值
}
```

顶层结构与 core/auth.Policy 兼容；`capability_parameters` 为扩展字段。

## GenDocs（从规范生成权限说明文档）

### GenDocs(def *SchemeDefinition) (string, error)

```go
func GenDocs(def *SchemeDefinition) (string, error)
```

生成 markdown 权限说明文档（能力目录/详细语义/通配符规则/角色映射/最小权限指南）。

### GenDocsToFile(def *SchemeDefinition, outputPath string) error

```go
func GenDocsToFile(def *SchemeDefinition, outputPath string) error
```

生成并写入 markdown 文件。

## MinCapability（最小权限校验）

### CapabilityClaim

```go
type CapabilityClaim struct {
    SchemeID   string         `json:"scheme_id"`
    Capability string         `json:"capability"`
    Parameters map[string]any `json:"parameters,omitempty"`
    Rationale  string         `json:"rationale,omitempty"`
}
```

AI 生成的单条能力声明。

### ParseCapabilityClaims(data []byte) ([]CapabilityClaim, error)

```go
func ParseCapabilityClaims(data []byte) ([]CapabilityClaim, error)
```

从 JSON 解析能力声明列表。

### (r *Registry) ValidateClaims(claims []CapabilityClaim) []ClaimResult

```go
func (r *Registry) ValidateClaims(claims []CapabilityClaim) []ClaimResult
```

校验声明合法性（scheme 存在、能力合法、参数已定义）。

### (r *Registry) CheckMinimalCapabilitySet(claims []CapabilityClaim, grantedPatterns []string) *MinSetReport

```go
func (r *Registry) CheckMinimalCapabilitySet(claims []CapabilityClaim, grantedPatterns []string) *MinSetReport
```

最小权限校验：合法性 + 冗余检测（被通配覆盖）+ 越权检测（身份未授权）。

## CLI 工具

| 工具 | 用途 |
|------|------|
| `gen-authz` | 从 capability.json 生成 authz.json（-list/-out/-verify/-verify-required/-trust-roots） |
| `gen-docs` | 从 capability.json 生成 markdown 权限说明文档 |
| `gen-capability` | 校验 AI 生成能力集 + 最小权限建议（-grants/-minimal） |
| `sign` | 签名 capability.json 生成 .p7s |
| `verify` | 验证 capability.json 的 .p7s 签名 |

## Helpers

### MatchCapability(id, pattern string) bool

```go
func MatchCapability(id, pattern string) bool
```

glob 语义通配匹配（精确/`*`/`?`/`a:b:*` 前缀）。与 types 同语义。

### (def *SchemeDefinition) ValidateSchemeRoles() ([]error, []string)

```go
func (def *SchemeDefinition) ValidateSchemeRoles() ([]error, []string)
```

校验角色定义：非通配 grants 必须被本方案 capabilities 覆盖（错误）；
通配 grants 未命中本地时视为跨 scheme 命名空间授权（警告）。

### ParseSchemeID(schemeID string) (vendor, product string, ok bool)

```go
func ParseSchemeID(schemeID string) (vendor, product string, ok bool)
```

解析 "vendor/product"。

### FormatSchemeID(vendor, product string) string

```go
func FormatSchemeID(vendor, product string) string
```

格式化为 "vendor/product"。

### ParseCapability(s string) (schemeID, capID string, ok bool)

```go
func ParseCapability(s string) (schemeID, capID string, ok bool)
```

解析 "vendor/product:capability_id"。

### FilterByScheme(caps []string, schemeID string) []string

```go
func FilterByScheme(caps []string, schemeID string) []string
```

按 scheme_id 过滤能力列表。

### Deduplicate(caps []string) []string

```go
func Deduplicate(caps []string) []string
```

去重。
