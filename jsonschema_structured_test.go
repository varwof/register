// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package register

import (
	"encoding/json"
	"errors"
	"testing"
)

// R-8 second path: a params_schema refusal carries a stable code and keeps the
// human message.
func TestSchemaStructuredError(t *testing.T) {
	raw := json.RawMessage(`{"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}`)
	err := validateParamsSchema(raw, map[string]any{"n": "seven"})
	if err == nil {
		t.Fatal("want a refusal")
	}
	var se *SchemaError
	if !errors.As(err, &se) {
		t.Fatalf("error is not a *SchemaError: %T", err)
	}
	if se.Code != "invalid_params_binding" {
		t.Fatalf("code: got %q", se.Code)
	}
	if se.Path != "n" {
		t.Fatalf("path: got %q", se.Path)
	}
	if got, want := se.Error(), `property "n": must be an integer`; got != want {
		t.Fatalf("message changed:\n got %s\nwant %s", got, want)
	}
}

// R-8 (nested): the structured path composes through nested property messages.
func TestSchemaStructuredErrorNestedPath(t *testing.T) {
	raw := json.RawMessage(`{"type":"object","properties":{"outer":{"type":"object","properties":{"inner":{"type":"integer"}}}}}`)
	err := validateParamsSchema(raw, map[string]any{"outer": map[string]any{"inner": "x"}})
	if err == nil {
		t.Fatal("want a refusal")
	}
	var se *SchemaError
	if !errors.As(err, &se) {
		t.Fatalf("error is not a *SchemaError: %T", err)
	}
	if se.Path != "outer.inner" {
		t.Fatalf("nested path: got %q", se.Path)
	}
}
