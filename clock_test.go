// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package register

import (
	"strings"
	"testing"
	"time"
)

func TestCheckObservedAtRejectsStaleClock(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	if err := CheckObservedAt("2026-10-22T00:00:00Z", now); err == nil || !strings.Contains(err.Error(), "allow-stale-clock") {
		t.Fatalf("stale observed_at accepted: %v", err)
	}
	if err := CheckObservedAt(now.Add(-time.Minute).Format(time.RFC3339), now); err != nil {
		t.Fatalf("fresh observed_at refused: %v", err)
	}
	if err := CheckObservedAt(now.Add(10*time.Minute).Format(time.RFC3339), now); err == nil {
		t.Fatal("future observed_at accepted")
	}
}
