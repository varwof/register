// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package projection

// The built-in projection set.
//
// CLC's own shape is the default: a document that is already a
// CLC-REQUIREMENT-v1 object is projected by clcNative, so the verifier has one
// path for evidence, native or foreign.  Foreign formats are registered
// alongside it and take precedence only when their own Match recognises the
// document (each matches on a distinct @version, so the order is a formality —
// but native stays last so an ambiguous document is read as CLC).
func init() {
	Register(&emiliaAEC{})
	Register(&clcNative{})
}
