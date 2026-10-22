// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)

package schemeadmin

import (
	"testing"
	"time"
)

func TestRevocationEffectiveTime(t *testing.T) {
	now := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	s := RegistryState{Revoked: []Revocation{{
		PackageDigest: "sha256:revoked",
		EffectiveTime: "2026-10-23T00:00:00Z",
	}}}
	revoked, err := s.isRevokedAt("sha256:revoked", now)
	if err != nil || revoked {
		t.Fatalf("future tombstone: revoked=%v err=%v", revoked, err)
	}
	revoked, err = s.isRevokedAt("sha256:revoked", now.Add(24*time.Hour))
	if err != nil || !revoked {
		t.Fatalf("effective tombstone: revoked=%v err=%v", revoked, err)
	}
}

func TestRevocationRejectsSelfReplacement(t *testing.T) {
	s := RegistryState{Revoked: []Revocation{{
		PackageDigest:     "sha256:revoked",
		ReplacementDigest: "sha256:revoked",
	}}}
	if _, err := s.isRevokedAt("sha256:revoked", time.Now()); err == nil {
		t.Fatal("self replacement accepted")
	}
}

func TestRevocationRejectsBadEffectiveTime(t *testing.T) {
	s := RegistryState{Revoked: []Revocation{{
		PackageDigest: "sha256:revoked",
		EffectiveTime: "not-a-time",
	}}}
	if _, err := s.isRevokedAt("sha256:revoked", time.Now()); err == nil {
		t.Fatal("invalid effective_time accepted")
	}
}
