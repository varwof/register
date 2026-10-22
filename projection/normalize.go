// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"fmt"
	"time"
)

// Normalize projects raw evidence with the first projector that matches it.
func Normalize(raw []byte, ctx Context) (*ProjectedView, error) {
	if ctx.Now.IsZero() {
		ctx.Now = time.Now().UTC()
	}
	p := Find(raw)
	if p == nil {
		return nil, fmt.Errorf("projection: no projector matched")
	}
	v, err := p.Project(raw, ctx)
	if err != nil {
		return nil, err
	}
	return &v, nil
}
