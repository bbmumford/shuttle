/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package shuttle

import (
	"testing"

	"github.com/bbmumford/loom/pkg/rpc/scope"
)

const platformRealm = "orbtr.platform"

func principalWith(t *testing.T, grants ...string) scope.AuthenticatedPrincipal {
	t.Helper()
	p, err := scope.NewAuthenticatedPrincipal(scope.NewScopeIdentity("pin", "partition-A", "svc-fleet"), grants)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDirectCapabilities(t *testing.T) {
	az := DirectCapabilities(platformRealm)
	cases := []struct {
		name     string
		grants   []string
		required string
		want     bool
	}{
		{"an exact grant admits", []string{"orbtr.platform:models.load"}, "orbtr.platform:models.load", true},
		{"a terminal wildcard admits every action on the resource", []string{"orbtr.platform:models.*"}, "orbtr.platform:models.evict", true},
		{"a deny beats the wildcard that would admit it",
			[]string{"orbtr.platform:models.*", "-orbtr.platform:models.evict"}, "orbtr.platform:models.evict", false},
		{"the deny spoils only what it covers",
			[]string{"orbtr.platform:models.*", "-orbtr.platform:models.evict"}, "orbtr.platform:models.load", true},
		{"another realm's wildcard never satisfies this realm", []string{"orbtr.ai:*"}, "orbtr.platform:models.load", false},
		{"a requirement outside the realm is refused even when held", []string{"orbtr.ai:inference.invoke"}, "orbtr.ai:inference.invoke", false},
		{"dotted scope strings are not capabilities", []string{"orbtr.platform.models.load"}, "orbtr.platform:models.load", false},
		{"no grants denies", nil, "orbtr.platform:models.load", false},
		{"a negative requirement is refused", []string{"orbtr.platform:models.*"}, "-orbtr.platform:models.load", false},
		{"an unparseable requirement is refused", []string{"orbtr.platform:models.*"}, "not-a-capability", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := az.HasCapability(principalWith(t, c.grants...), c.required); got != c.want {
				t.Fatalf("HasCapability(%v, %q) = %v, want %v", c.grants, c.required, got, c.want)
			}
		})
	}
}

// Through loom's Policy: a capability-arm requirement is admitted only for the
// principal whose minted grants confer it.
func TestDirectCapabilitiesThroughPolicy(t *testing.T) {
	policy := scope.NewPolicy(DirectCapabilities(platformRealm))
	req := scope.Capability("orbtr.platform:training.submit")
	if ok, why := policy.Authorize(req, principalWith(t, "orbtr.platform:training.submit")); !ok {
		t.Fatalf("granted platform peer refused: %s", why)
	}
	if ok, _ := policy.Authorize(req, principalWith(t, "orbtr.ai:inference.invoke")); ok {
		t.Fatal("a customer principal holding only an orbtr.ai grant was admitted to a platform op")
	}
}
