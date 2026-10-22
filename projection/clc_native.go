// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"encoding/json"
	"time"

	"github.com/varwof/register/semantics"
)

// clcNative is the default projector: a document that is already a
// CLC-REQUIREMENT-v1 object needs no translation, and it is the shape every
// foreign format is projected *into*.  Registering it makes CLC the default
// path — a document in CLC's own shape is handled uniformly with a projected
// one, and a foreign format only takes over when its own projector matches
// first.
type clcNative struct{}

func (c *clcNative) ID() string { return "clc/requirement-v1" }

func (c *clcNative) Match(raw []byte) bool {
	var probe struct {
		Version string `json:"@version"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return false
	}
	return probe.Version == semantics.RequirementVersion
}

func (c *clcNative) Project(raw []byte, ctx Context) (ProjectedView, error) {
	req, err := semantics.ParseRequirement(raw)
	if err != nil {
		return ProjectedView{}, err
	}
	meta := map[string]string{
		"projector_id":  c.ID(),
		"source_format": semantics.RequirementVersion,
		"mapped_at_utc": ctx.Now.UTC().Format(time.RFC3339),
	}
	if !ctx.Now.IsZero() {
		meta["project_ctx_now_utc"] = ctx.Now.UTC().Format(time.RFC3339)
	}
	return ProjectedView{
		Requirement: &req,
		Facts:       []semantics.EvidenceFact{},
		// Nothing to carry: the document was already in the target shape.  An
		// empty residual list here means "no loss", not "not examined".
		Residuals: nil,
		Meta:      meta,
	}, nil
}
