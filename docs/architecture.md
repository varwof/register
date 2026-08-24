# Architecture

## 信任链

```
Varwof Root CA (离线冷备)
    │
    ├── Policy Sub-CA (策略子CA)
    │       │
    │       ├── Register Sub-CA (能力注册子CA)
    │       │       │
    │       │       ├── oracle/mysql (产品证书)
    │       │       ├── varwof/core
    │       │       ├── varwof/gateway
    │       │       └── x-vendor/acme
    │       │
    │       └── (未来: Audit Sub-CA 等)
    │
    └── Issuing Sub-CA (终端实体证书)
```

## 安全隔离

| 层级 | 证书 | 泄露影响 | 恢复 |
|------|------|---------|------|
| L0 | Root CA | 全套废弃 | 重新部署 |
| L1 | Policy Sub-CA | 策略层 | Root 吊销重签 |
| L2 | Register Sub-CA | 产品证书 | Policy 吊销重签 |
| L3 | 产品证书 | 该产品 | Register 吊销重签 |

## 校验流程

```
1. Agent 声明能力 → AIC
2. 网关加载 Register
3. 逐条验证 → 有效/无效
4. 子集检查 → 越权/合规
5. 放行/拒绝
```

## 签名流程

```
产品方签署 capability.json → .p7s
Register 验证签名链 → 发布
Agent/网关验证 .p7s → 信任
```

## 目录结构

```
register/
├── data/                        ← scheme JSON 定义（纯数据）
│   ├── varwof/                  # 自有产品
│   │   ├── core/v1.json
│   │   ├── gateway/v1.json
│   │   ├── constraint/v1.json
│   │   └── demo-mysql/v1/v1.json
│   ├── oracle/                  # 第三方
│   │   └── mysql/v1.json
│   └── x-vendor/                # 私有扩展
│       └── acme/v1.json
├── loader.go                    ← Go 代码（go:embed data/）
├── schema.go
├── registry.go
└── ...
```

## 版本管理

### Scheme ID 命名

格式：`{vendor}/{product}-v{major}`

- `varwof/demo-mysql-v1` — 大版本 1
- `varwof/demo-mysql-v2` — 大版本 2（breaking change）
- `oracle/mysql-v3` — 大版本 3

大版本号嵌入 scheme_id，确保 breaking change 时：
1. 新旧方案**同时注册**，不破坏现有证书
2. 迁移期双方案并存
3. 旧方案可继续签发，新方案逐步接管

### 目录结构

```
register/data/{vendor}/{product}-v{major}/
├── v1.json    ← 小版本 1（初始）
├── v2.json    ← 小版本 2（向后兼容，新增能力/参数）
└── v3.json    ← 小版本 3（向后兼容）
```

### 版本兼容性规则

| 变更类型 | 兼容性 | 做法 |
|----------|--------|------|
| 新增能力（如 `TRUNCATE:*`） | ✅ 向后兼容 | 新增小版本 JSON，capabilities 为旧版超集 |
| 新增参数（有默认值） | ✅ 向后兼容 | 新增小版本 JSON，参数带 default |
| 删除/拆分能力 | ❌ Breaking | 新建大版本目录（`v2/`），新 scheme_id |
| 参数语义变更 | ❌ Breaking | 新建大版本目录（`v2/`），新 scheme_id |

### Grant 格式

```
{scheme_id}:{capability_id}
```

示例：
- `varwof/demo-mysql-v1:SELECT:*` — 匹配 v1 最新小版本
- `varwof/demo-mysql-v2:DELETE:*` — 匹配 v2 最新小版本

加载器行为：按 scheme_id 查找，同 scheme_id 多个小版本 JSON 取最新。

### 迁移流程

```
1. 发布 v2（新 scheme_id: varwof/demo-mysql-v2）
2. authz.json 同时添加 v1 和 v2 角色
3. 新签发的 AIC 用 v2 scheme_id
4. 旧 AIC 到期后自然淘汰
5. 迁移完成，移除 v1
```

## 扩展方式

### 公共标准（v1 方案）

```bash
mkdir -p register/data/{vendor}/{product}-v1
cat > register/data/{vendor}/{product}-v1/v1.json << 'EOF'
{
  "scheme_id": "{vendor}/{product}-v1",
  ...
}
EOF
```

### 大版本升级（breaking change）

```bash
mkdir -p register/data/{vendor}/{product}-v2
cat > register/data/{vendor}/{product}-v2/v1.json << 'EOF'
{
  "scheme_id": "{vendor}/{product}-v2",
  ...
}
EOF
```

### 小版本升级（向后兼容）

```bash
cat > register/data/{vendor}/{product}-v1/v2.json << 'EOF'
{
  "scheme_id": "{vendor}/{product}-v1",
  "version": "1.2.0",
  "capabilities": [
    ... (保留旧能力 + 新增)
  ]
}
EOF
```

### 私有扩展

```bash
mkdir register/data/x-{vendor}/{product}-v1
cat > register/data/x-{vendor}/{product}-v1/v1.json << 'EOF'
{
  "scheme_id": "x-{vendor}/{product}-v1",
  ...
}
EOF
```
