package register

import (
	"path/filepath"
	"testing"
)

// TestDatabaseV1Registered verifies the canonical std/database-v1
// scheme is loadable from the capability data tree, carries structured
// params_schema, and its capabilities validate.
func TestDatabaseV1Registered(t *testing.T) {
	reg, err := LoadFromDir(filepath.Join("..", "capability", "data"))
	if err != nil {
		t.Fatal(err)
	}
	def, ok := reg["std/database-v1"]
	if !ok {
		t.Fatalf("std/database-v1 not found in capability data")
	}
	if len(def.Capabilities) < 7 {
		t.Fatalf("expected >=7 capabilities, got %d", len(def.Capabilities))
	}
	var selectCap *CapabilityEntry
	for i := range def.Capabilities {
		if def.Capabilities[i].ID == "query:SELECT" {
			selectCap = &def.Capabilities[i]
		}
	}
	if selectCap == nil {
		t.Fatalf("query:SELECT capability missing")
	}
	if len(selectCap.ParamsSchema) == 0 {
		t.Fatalf("query:SELECT must carry params_schema")
	}

	r := NewRegistry()
	r.Register(def)
	for _, id := range []string{"std/database-v1:query:SELECT", "std/database-v1:query:INSERT", "std/database-v1:admin:TRUNCATE"} {
		if _, _, err := r.ValidateCapability(id); err != nil {
			t.Fatalf("registered capability %s must validate: %v", id, err)
		}
	}
	if _, _, err := r.ValidateCapability("std/database-v1:query:EXPLAIN"); err == nil {
		t.Fatalf("unregistered capability must fail")
	}
}
