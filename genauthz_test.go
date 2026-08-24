package register

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 构造一个最小可用的测试方案（带角色定义）。
func writeTestScheme(t *testing.T, dir, id string, roles map[string]RoleDef) string {
	t.Helper()
	def := SchemeDefinition{
		SchemeID: id,
		Name:     id,
		Version:  "1.0.0",
		Vendor:   "varwof",
		Product:  "test",
		Capabilities: []CapabilityEntry{
			{ID: "ca:list", Description: "列出 CA"},
			{ID: "ca:create", Description: "创建 CA"},
			{ID: "cert:issue", Description: "签发",
				Parameters: map[string]ParameterDef{
					"max_validity_days": {Type: "int", Default: float64(365), Min: 1.0, Max: 3650.0},
				}},
			{ID: "log:read", Description: "读日志"},
		},
		Roles: roles,
	}
	path := filepath.Join(dir, "scheme.json")
	if err := WriteScheme(&def, path); err != nil {
		t.Fatalf("write scheme: %v", err)
	}
	return path
}

// writeTestSchemeCustom 写入带自定义能力列表的测试方案。
func writeTestSchemeCustom(t *testing.T, dir, id string, caps []CapabilityEntry, roles map[string]RoleDef) string {
	t.Helper()
	def := SchemeDefinition{
		SchemeID:     id,
		Name:         id,
		Version:      "1.0.0",
		Vendor:       "varwof",
		Product:      "test",
		Capabilities: caps,
		Roles:        roles,
	}
	path := filepath.Join(dir, strings.ReplaceAll(id, "/", "-")+"-scheme.json")
	if err := WriteScheme(&def, path); err != nil {
		t.Fatalf("write scheme: %v", err)
	}
	return path
}

func TestGenAuthzBasic(t *testing.T) {
	dir := t.TempDir()
	roles := map[string]RoleDef{
		"admin": {DisplayName: "管理员", Profiles: []string{"m-admin"}, OUs: []string{"admin", "Admin"},
			Grants: []string{"ca:list", "ca:create", "cert:issue", "log:read"}},
		"readonly": {DisplayName: "只读", OUs: []string{"readonly"},
			Grants: []string{"ca:list", "log:read"}},
		"agent": {DisplayName: "Agent", OUs: nil,
			Grants: []string{"gateway:*"}},
	}
	p := writeTestScheme(t, dir, "varwof/core", roles)
	// 从第二个方案（gateway 命名空间角色）聚合 gateway: 前缀
	gwRoles := map[string]RoleDef{
		"gateway:admin": {DisplayName: "网关管理员", OUs: []string{"gateway:admin"},
			Grants: []string{"proxy:*", "admin:config"}},
	}
	gwCaps := []CapabilityEntry{
		{ID: "proxy:http", Description: "HTTP 代理"},
		{ID: "proxy:tcp", Description: "TCP 代理"},
		{ID: "admin:config", Description: "配置管理"},
	}
	gp := writeTestSchemeCustom(t, dir, "varwof/gateway", gwCaps, gwRoles)

	doc, err := GenAuthz(GenAuthzConfig{SchemePaths: []string{p, gp}, Version: "v2"})
	if err != nil {
		t.Fatalf("GenAuthz: %v", err)
	}
	if doc.Version != "v2" {
		t.Errorf("version = %q, want v2", doc.Version)
	}
	if len(doc.Roles) != 3 {
		t.Errorf("roles = %d, want 3", len(doc.Roles))
	}
	// OU 映射
	for ou, want := range map[string]string{"admin": "admin", "Admin": "admin", "readonly": "readonly"} {
		if got := doc.OUMapping[ou]; got != want {
			t.Errorf("ou_mapping[%s] = %q, want %q", ou, got, want)
		}
	}
	// 网关命名空间
	ns, ok := doc.GatewayNamespaces["gateway:"]
	if !ok {
		t.Fatalf("missing gateway_namespaces[gateway:]")
	}
	if ns.Grants[0] != "gateway:*" {
		t.Errorf("ns grant = %q, want gateway:*", ns.Grants[0])
	}
	// 参数默认值
	params := doc.CapabilityParameters["varwof/core:cert:issue"]
	if params == nil {
		t.Fatalf("missing capability_parameters for cert:issue")
	}
	if v, _ := params["max_validity_days"].(float64); v != 365 {
		t.Errorf("max_validity_days = %v, want 365", params["max_validity_days"])
	}
}

func TestGenAuthzRoleCoverageError(t *testing.T) {
	dir := t.TempDir()
	roles := map[string]RoleDef{
		"bad": {Grants: []string{"ca:list", "no:such-capability"}},
	}
	p := writeTestScheme(t, dir, "varwof/core", roles)
	_, err := GenAuthz(GenAuthzConfig{SchemePaths: []string{p}})
	if err == nil {
		t.Fatal("expected error for uncovered grant, got nil")
	}
}

func TestGenAuthzCrossSchemeWildcardOK(t *testing.T) {
	dir := t.TempDir()
	roles := map[string]RoleDef{
		"agent": {Grants: []string{"gateway:*"}},
	}
	p := writeTestScheme(t, dir, "varwof/core", roles)
	doc, err := GenAuthz(GenAuthzConfig{SchemePaths: []string{p}})
	if err != nil {
		t.Fatalf("GenAuthz cross-scheme wildcard: %v", err)
	}
	if len(doc.Roles) != 1 {
		t.Errorf("roles = %d, want 1", len(doc.Roles))
	}
}

func TestGenAuthzToFile(t *testing.T) {
	dir := t.TempDir()
	roles := map[string]RoleDef{
		"admin": {DisplayName: "管理员", OUs: []string{"admin"},
			Grants: []string{"ca:list", "ca:create"}},
	}
	p := writeTestScheme(t, dir, "varwof/core", roles)
	out := filepath.Join(dir, "out", "authz.json")
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := GenAuthzToFile(GenAuthzConfig{SchemePaths: []string{p}}, out); err != nil {
		t.Fatalf("GenAuthzToFile: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty output")
	}
}

func TestMatchCapabilityWildcard(t *testing.T) {
	cases := []struct {
		id, pat string
		want    bool
	}{
		{"ca:list", "ca:list", true},
		{"ca:list", "ca:*", true},
		{"ca:create", "ca:*", true},
		{"cert:issue", "ca:*", false},
		{"gateway:proxy", "gateway:*", true},
		{"gateway:admin:config", "gateway:*", true},
		{"ca:list", "*", true},
		{"ca:list", "ca:list:*", false},
		{"ca:list", "?", false},
	}
	for _, c := range cases {
		if got := MatchCapability(c.id, c.pat); got != c.want {
			t.Errorf("MatchCapability(%q, %q) = %v, want %v", c.id, c.pat, got, c.want)
		}
	}
}
