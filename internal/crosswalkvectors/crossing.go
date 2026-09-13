// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

// 反向映射：CLC 裁决 → AEB crossing 所需的成员（"我们这边能供什么"）。
//
// 正方向（外部表示 → CLC）在同目录的 MapProfile 里；这里是反方向，落点是 EMILIA 的
// EP-AIC-AEB-CROSSING-MAPPING-v0.2 里 action_projection / admission_domain / rules 那几节
// 要求**源侧**提供的东西。
//
// 关键纪律：**只声明 CLC 能确立的**。素材动作标识（caid/action_digest）由效果边界从
// ObservedAction 构造；原生验证结果（VERIFIED）与状态新鲜度属于原生验证方；密钥绑定属于
// 原生工件 —— 这些不在我们的裁决里，因此**列进 Unsupplied 并给出稳定原因**，而不是
// 留空、更不是编一个。
package crosswalkvectors

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/varwof/register/semantics"
)

// Unsupplied names a crossing member this side cannot establish, and why.
type Unsupplied struct {
	Member string `json:"member"`
	Reason string `json:"reason"`
}

// CrossingProjection is what a CLC decision contributes to an AEB crossing
// record: the members we can establish, plus the ones we explicitly do not.
type CrossingProjection struct {
	// Verdict / Reason are the CLC verdict and its stable reason code.
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
	// RequestedCapabilityDigest is sha256 over the JCS canonical Operation
	// (capability id + params) — exactly what CLC decided about.  It plays the
	// role of the crossing profile's requested_capability_digest.
	RequestedCapabilityDigest string `json:"requestedCapabilityDigest"`
	// CLCRecordDigest is the decision record's input digest: the handle to the
	// replayable record.
	CLCRecordDigest string `json:"clcRecordDigest"`
	// Unresolved are the §8.4 residual obligations (empty when fully decided).
	Unresolved []string `json:"unresolved,omitempty"`
	// AuthoritySemanticsPreserved is true: CLC consumes the native authority's
	// scope semantics rather than reimplementing them.
	AuthoritySemanticsPreserved bool `json:"authoritySemanticsPreserved"`
	// AuthorizationDecision is always false: a CLC verdict is a scope decision,
	// never the relying party's AUTHORIZED.  The crossing's own decision stays
	// with AEB/Gate.
	AuthorizationDecision bool `json:"authorizationDecision"`
	// Unsupplied lists what this side does not establish.
	Unsupplied []Unsupplied `json:"unsupplied"`
}

// unsuppliedMembers is the fixed list, with the reason each one belongs to
// another layer (the same boundary the CLC text states in Section 11).
var unsuppliedMembers = []Unsupplied{
	{"native_result", "native verifier output: CLC never reimplements signature, delegation or status validation"},
	{"caid", "material action identity is constructed by the effect boundary (ObservedAction), not by the scope decision"},
	{"action_digest", "same as caid: the executor's material action, not the requested capability"},
	{"status.checked_at", "status freshness belongs to the native status source"},
	{"status.source_head_digest", "status freshness belongs to the native status source"},
	{"principal_binding", "key binding (jkt / SPKI) belongs to the native artifact profile"},
}

// MapCrossing projects one CLC decision into the crossing-facing members.
func MapCrossing(grants []semantics.Grant, op semantics.Operation) (CrossingProjection, error) {
	canonical, err := semantics.CanonicalJSON(op)
	if err != nil {
		return CrossingProjection{}, err
	}
	sum := sha256.Sum256(canonical)

	rec, err := semantics.Record(grants, op)
	if err != nil {
		return CrossingProjection{}, err
	}
	decision := semantics.AuthorizeSet(grants, op)

	// The record and the projection must agree: both are computed from the same
	// inputs, so a divergence is a programming error rather than a policy one.
	if rec.Verdict != decision.Verdict {
		return CrossingProjection{}, fmt.Errorf("crossing: record verdict %q != decision %q", rec.Verdict, decision.Verdict)
	}

	return CrossingProjection{
		Verdict:                     decision.Verdict,
		Reason:                      canonicalReason(decision.Reason),
		RequestedCapabilityDigest:   "sha256:" + hex.EncodeToString(sum[:]),
		CLCRecordDigest:             "sha256:" + hex.EncodeToString(rec.InputDigest.Value),
		Unresolved:                  append([]string(nil), decision.Unresolved...),
		AuthoritySemanticsPreserved: true,
		AuthorizationDecision:       false,
		Unsupplied:                  unsuppliedMembers,
	}, nil
}
