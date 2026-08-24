package ruleexec

import (
	pki "github.com/varwof/types"
)

// MapHTTPRequest converts gateway-core PluginContext facts (including
// the optional HTTP request fields) into the request map consumed by
// rule conditions: request.method / request.path / request.query /
// request.headers plus target/client_cn/agent_id/roles.
//
// HTTP-facing gateways populate ctx.Method/Path/Query/Headers; the
// TCP admission path only provides Target/ClientCN/Roles/AgentId.
func MapHTTPRequest(ctx *pki.PluginContext) map[string]any {
	req := map[string]any{
		"target":    ctx.Target,
		"client_cn": ctx.ClientCN,
		"agent_id":  ctx.AgentId,
		"roles":     ctx.Roles,
	}
	if ctx.Method != "" {
		req["method"] = ctx.Method
	}
	if ctx.Path != "" {
		req["path"] = ctx.Path
	}
	if ctx.Query != nil {
		q := make(map[string]any, len(ctx.Query))
		for k, vs := range ctx.Query {
			if len(vs) == 1 {
				q[k] = vs[0] // single value: plain string for eq comparisons
			} else {
				q[k] = vs
			}
		}
		req["query"] = q
	}
	if ctx.Headers != nil {
		h := make(map[string]any, len(ctx.Headers))
		for k, v := range ctx.Headers {
			h[k] = v
		}
		req["headers"] = h
	}
	return req
}
