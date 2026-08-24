# 全球能力注册中心部署方案（存档稿）

> 状态：**待仓库创建后执行**（2026-08-24 存档）
> 目标：基于 GitHub（PR 治理）+ Cloudflare（静态分发）+ PKCS#7（验签消费），
> 实现"全球互通、保持开放"的能力注册中心。
> 前置：varwof.com / varwof.org 已在 Cloudflare 托管；可创建公开 GitHub 仓库。

## 1. 总体模式

**PR 治理 + 边缘分发 + 验签消费**（与 IANA 注册表 / OpenAPI 注册中心 / Homebrew
同构）：

```
GitHub 仓库（能力数据 data/{vendor}/{product}-v{major}/v{minor}.json）
   │  PR → 维护者审核 → merge
   ▼
CI（GitHub Actions，merge 时自动）
   ① validate   （复用 register 校验：scheme 格式/能力/params_schema）
   ② publish    （复用 PublishRules：default.json 字节副本 + .p7s + manifest.json）
   ③ deploy     （wrangler pages deploy → registry.varwof.org）
   ▼
Cloudflare Pages（纯静态，天然 CDN/边缘缓存）
   /schemes/{vendor}/{product}-v{major}/default.json   (+ .p7s)
   /schemes/{vendor}/{product}-v{major}/v{minor}.json
   /manifest.json                                        (方案清单 + 最新版本)
   ▼
消费者（core/gateway / 任意组织）
   GET default.json + .p7s → 验签（固定注册中心公钥）→ 作为 capability_schemes 使用
```

关键设计：注册中心数据是**不可变文件 + 签名**，静态托管即可，无需数据库/服务器。
Cloudflare Pages 是最合适的载体（对比 Workers 多余）。

## 2. 域名分配

| 域名 | 用途 |
|------|------|
| `registry.varwof.org` | 注册中心数据面（/schemes/...、/manifest.json） |
| `varwof.com` | 门户 / 文档 / 治理说明 |

## 3. 仓库形态（待创建）

建议：独立公开仓库 `github.com/varwof/capability-registry`：

```
capability-registry/
├── data/{vendor}/{product}-v{major}/v{minor}.json   # 能力数据（PR 提交）
├── trust/registry-root.pem                          # 注册中心签名公钥（消费者固定）
├── .github/workflows/publish.yml                    # validate → publish → deploy
├── wrangler.toml / pages 配置
└── README.md                                        # 贡献/治理说明
```

`register` 模块（校验/发布器/加载器）作为依赖使用，代码与数据分离，利于开放协作。

## 4. CI 步骤（publish.yml）

```yaml
on: push (main)
jobs:
  publish:
    - go build 校验器/发布器（复用 register.PublishRules）
    - 校验全部 data/*.json（ValidateSchemeID / capabilities / params_schema）
    - 生成 default.json（最高小版本字节副本）+ PKCS#7 签名 + manifest.json
    - wrangler pages deploy（用 GH Secrets: CLOUDFLARE_API_TOKEN/ACCOUNT_ID）
```

签名密钥：注册中心私钥放 GitHub Actions Secret，merge 时统一重签（推荐模型：
消费者只固定一个公钥，贡献者不碰签名）。

## 5. 对外端点（消费契约）

| 端点 | 内容 | 缓存 |
|------|------|------|
| `/schemes/{vendor}/{product}-v{major}/v{minor}.json` | 版本化规范 | 不可变（长缓存） |
| `/schemes/{vendor}/{product}-v{major}/default.json` | 最新兼容版本 | 短 TTL + revalidate |
| `/schemes/.../default.json.p7s` | detached 签名 | 与 default.json 同步 |
| `/manifest.json` | 方案清单 + latest 指针 | 短 TTL |

Content-Type: `application/json`；CORS 开放（程序化消费）。

## 6. 治理约定

- `std/` 命名空间：公共标准，PR + 维护者审核（防抢注、可追溯）；
- 厂商命名空间（`vendor/...`）：自服务注册，PR 合入即发布；
- 版本规则（沿用现有）：小版本只增不破（新增能力/参数带默认值）；破坏性变更
  开新大版本目录（`-v{major}`），default.json 各自独立；
- 审核清单：scheme 命名、能力语义文档、params_schema 合法性、示例。

## 7. 待仓库建好后的实施清单（按本地可验证顺序）

1. **消费者拉取 + 验签**：`register` loader 新增 `LoadFromURL`（fetch default.json
   + .p7s → 验签 → 加载）；core/gateway 的 `capability_schemes` 支持 URL。
2. **本地 registry-serve**：Go stdlib 小命令把 data 目录当静态站点跑（端点/
   Content-Type/缓存头），本机验证"拉取+验签"闭环，再原样部署 Pages。
3. **CI + Pages 模板**：publish.yml + wrangler/Pages 配置 + 签名密钥管理。
4. **域名解析**：registry.varwof.org → Cloudflare Pages（Pages 自带
   custom domain）。

## 8. 待决策

1. 签名模型：维护者合并时统一重签（推荐）vs 贡献者各自签名 + 链校验；
2. 数据仓库独立（推荐）vs 与 register 代码同仓；
3. default.json 缓存策略（短 TTL 默认 vs 长缓存 + webhook 失效）；
4. 是否提供 web UI（列表/搜索，Pages 静态即可支持）。
