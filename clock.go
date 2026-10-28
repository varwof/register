// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package register

import (
	"fmt"
	"time"
)

// MaxObservedAtSkew bounds how far a deployer's observed_at may be from the
// wall clock.  The verification libraries evaluate certificate and artifact
// validity at the caller-supplied instant, so a stale policy clock silently
// widens every freshness decision; the command-line tools refuse it by default.
const MaxObservedAtSkew = 5 * time.Minute

// CheckObservedAt rejects an observed_at that is not close to now.
func CheckObservedAt(observedAt string, now time.Time) error {
	t, err := time.Parse(time.RFC3339, observedAt)
	if err != nil {
		return fmt.Errorf("observed_at %q is not RFC3339", observedAt)
	}
	delta := now.Sub(t)
	if delta < 0 {
		delta = -delta
	}
	if delta > MaxObservedAtSkew {
		return fmt.Errorf("observed_at %s is %s from the wall clock (limit %s); pass -allow-stale-clock to override",
			observedAt, delta.Round(time.Second), MaxObservedAtSkew)
	}
	return nil
}
