// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

import (
	"time"

	"github.com/varwof/register/semantics"
)

// ProjectedView is the minimal view the CLC decision layer needs from an
// external evidence document.
type ProjectedView struct {
	Action               *semantics.ActionId
	Facts                []semantics.EvidenceFact
	Requirement          *semantics.Requirement
	Residuals            []string
	RequiredNativeChecks []string
	Meta                 map[string]string
}

// Context carries the pins a projection needs.
type Context struct {
	Now       time.Time
	Initiator string
	Executor  string

	// RoleMap bridges a foreign role/component identifier to the CLC evidence
	// role facts are typed by.  A mapping is never guessed: the relying party
	// pins it (the same way an Action-Mapping Profile is pinned).  An entry
	// that is absent leaves the foreign identifier in place and surfaces a
	// residual instead of silently inventing a bridge.
	RoleMap map[string]string
}

// Projector recognises and projects one external evidence format.
type Projector interface {
	ID() string
	Match(raw []byte) bool
	Project(raw []byte, ctx Context) (ProjectedView, error)
}
