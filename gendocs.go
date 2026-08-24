// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// GenDocs generates a markdown permission documentation from a capability.json scheme.
// The documentation targets both human readers and AI models: fully describing each capability's semantics,
// parameter constraints, wildcard rules, role and grants mappings, serving as the authoritative reference
// for AI to generate minimal privilege capability sets.
//
// Output markdown structure:
//   - Product overview + capability catalog table
//   - Detailed capability semantics (summary/usage/when_not/examples/parameters/related)
//   - Wildcard and matching rules
//   - Role and grants mapping
//   - Least privilege principle guidelines
func GenDocs(def *SchemeDefinition) (string, error) {
	if def == nil {
		return "", fmt.Errorf("gen-docs: nil scheme")
	}
	var b strings.Builder

	// Title and overview
	fmt.Fprintf(&b, "# %s 权限说明\n\n", def.Name)
	fmt.Fprintf(&b, "> scheme_id: `%s` · 版本 `%s` · 厂商 `%s` / 产品 `%s`\n\n",
		def.SchemeID, def.Version, def.Vendor, def.Product)
	if def.Description != "" {
		fmt.Fprintf(&b, "%s\n\n", def.Description)
	}
	fmt.Fprintf(&b, "完整能力标识格式：`%s:capability_id`（如 `%s:cert:issue`）。\n\n",
		def.SchemeID, def.SchemeID)

	// Capability catalog table
	b.WriteString("## 能力目录\n\n")
	b.WriteString("| 能力 | 摘要 | 相关能力 |\n")
	b.WriteString("|------|------|----------|\n")
	entries := make([]CapabilityEntry, len(def.Capabilities))
	copy(entries, def.Capabilities)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	for _, c := range entries {
		summary := c.Summary
		if summary == "" {
			summary = c.Description
		}
		related := strings.Join(c.Related, ", ")
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", c.ID, summary, related)
	}
	b.WriteString("\n")

	// Detailed capability semantics
	b.WriteString("## 能力详细语义\n\n")
	b.WriteString("> 阅读指引：本节的 `usage`/`when_not`/`examples` 用于判断**何时需要该能力、何时不应授予**。AI 生成最小权限集合时以此为依据。\n\n")
	for _, c := range entries {
		fmt.Fprintf(&b, "### `%s`\n\n", c.ID)
		if c.Summary != "" {
			fmt.Fprintf(&b, "**摘要**：%s\n\n", c.Summary)
		}
		if c.Description != "" {
			fmt.Fprintf(&b, "**说明**：%s\n\n", c.Description)
		}
		if c.Usage != "" {
			fmt.Fprintf(&b, "**何时需要**：%s\n\n", c.Usage)
		}
		if c.WhenNot != "" {
			fmt.Fprintf(&b, "**何时不应授予**：%s\n\n", c.WhenNot)
		}
		if len(c.Examples) > 0 {
			b.WriteString("**示例**：\n\n")
			for _, e := range c.Examples {
				fmt.Fprintf(&b, "- %s\n", e)
			}
			b.WriteString("\n")
		}
		if len(c.Parameters) > 0 {
			b.WriteString("**参数**：\n\n")
			b.WriteString("| 参数 | 类型 | 默认值 | 约束 | 说明 |\n")
			b.WriteString("|------|------|--------|------|------|\n")
			keys := make([]string, 0, len(c.Parameters))
			for k := range c.Parameters {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				p := c.Parameters[k]
				defv := ""
				if p.Default != nil {
					defv = fmt.Sprintf("%v", p.Default)
				}
				constraints := []string{}
				if p.Min != nil {
					constraints = append(constraints, fmt.Sprintf("min=%v", p.Min))
				}
				if p.Max != nil {
					constraints = append(constraints, fmt.Sprintf("max=%v", p.Max))
				}
				if len(p.Enum) > 0 {
					constraints = append(constraints, "enum="+strings.Join(p.Enum, "/"))
				}
				if p.Required {
					constraints = append(constraints, "required")
				}
				fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s | %s |\n",
					k, p.Type, defv, strings.Join(constraints, ", "), p.Description)
			}
			b.WriteString("\n")
		}
		if len(c.Related) > 0 {
			related := make([]string, 0, len(c.Related))
			for _, r := range c.Related {
				related = append(related, "`"+r+"`")
			}
			fmt.Fprintf(&b, "**相关能力**：%s\n\n", strings.Join(related, ", "))
		}
		b.WriteString("---\n\n")
	}

	// Wildcard and matching rules
	b.WriteString("## 通配符与匹配规则\n\n")
	b.WriteString("grant/能力匹配支持 glob 通配，用于角色授权与最小权限校验：\n\n")
	b.WriteString("| 模式 | 含义 | 示例 |\n")
	b.WriteString("|------|------|------|\n")
	b.WriteString("| `capability_id` | 精确匹配 | `cert:issue` |\n")
	b.WriteString("| `domain:*` | 前缀通配（该域下全部动作） | `ca:*` 匹配 `ca:list`、`ca:create` |\n")
	b.WriteString("| `*` / `**` | 全量通配（所有能力） | 危险，尽量避免 |\n")
	b.WriteString("| `?` | 单字符通配 | 少用 |\n\n")
	b.WriteString("**最小权限原则**：角色 grants 与 AI 生成的能力集应尽量使用**精确能力**，仅在确实需要整个域时使用 `domain:*`。\n\n")

	// Roles and grants
	if len(def.Roles) > 0 {
		b.WriteString("## 角色与授权映射\n\n")
		roleKeys := make([]string, 0, len(def.Roles))
		for k := range def.Roles {
			roleKeys = append(roleKeys, k)
		}
		sort.Strings(roleKeys)
		for _, role := range roleKeys {
			rd := def.Roles[role]
			fmt.Fprintf(&b, "### 角色 `%s`\n\n", role)
			if rd.DisplayName != "" {
				fmt.Fprintf(&b, "**名称**：%s\n\n", rd.DisplayName)
			}
			if len(rd.Profiles) > 0 {
				fmt.Fprintf(&b, "**Profiles**：`%s`\n\n", strings.Join(rd.Profiles, "`, `"))
			}
			if len(rd.OUs) > 0 {
				fmt.Fprintf(&b, "**可绑定 OU**：`%s`\n\n", strings.Join(rd.OUs, "`, `"))
			}
			b.WriteString("**授权能力（grants）**：\n\n")
			for _, g := range rd.Grants {
				fmt.Fprintf(&b, "- `%s`\n", g)
			}
			b.WriteString("\n")
		}
	}

	// Least privilege generation guidelines
	b.WriteString("## 最小权限生成指南（AI/开发者）\n\n")
	b.WriteString("为任务生成能力集合时遵循：\n\n")
	b.WriteString("1. **只授予任务必需能力**：对照各能力 `usage`（何时需要）判断，`when_not` 明确说明的不授予。\n")
	b.WriteString("2. **精确优先**：能精确到 `capability_id` 就不用通配；能用单个能力就不用域通配 `domain:*`。\n")
	b.WriteString("3. **参数收窄**：有 `parameters` 的能力，按任务实际需要设置默认值/范围，宁可窄勿宽。\n")
	b.WriteString("4. **只读优先**：只读能力（`*:list`、`*:read`、`*:view`）优先于写能力。\n")
	b.WriteString("5. **禁用危险能力**：`key:recover`、`ca:delete`、`config:write` 等敏感能力默认不授予，除非任务明确需要。\n")
	b.WriteString("6. **去除冗余**：已由通配覆盖的精确能力可省略；与任务无关的能力全部删除。\n\n")

	return b.String(), nil
}

// GenDocsToFile generates markdown permission documentation and writes it to a file.
func GenDocsToFile(def *SchemeDefinition, outputPath string) error {
	md, err := GenDocs(def)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, []byte(md), 0o644); err != nil {
		return fmt.Errorf("gen-docs: write %s: %w", outputPath, err)
	}
	return nil
}
