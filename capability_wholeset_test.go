/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package shuttle

import (
	"fmt"
	"testing"

	"github.com/bbmumford/warrant"
)

// grantsOf builds n distinct well-formed capabilities of the platform realm, so a test can
// stand a held set at warrant's per-set limit beside one past it.
func grantsOf(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("%s:res%d.read", platformRealm, i))
	}
	return out
}

// A grant that names a realm before a colon and does not parse refuses the whole held set,
// so it denies a requirement the valid grants beside it confer. Each case pairs the spoiled
// set with the same set spelled correctly, which is what distinguishes a whole-set refusal
// from a parse that happens to drop one string.
func TestDirectCapabilitiesRefusesASetWholeOnAMalformedGrant(t *testing.T) {
	az := DirectCapabilities(platformRealm)
	required := "orbtr.platform:models.load"
	cases := []struct {
		name    string
		valid   []string
		spoiled []string
	}{
		{
			"a mistyped deny refuses the set that holds it",
			[]string{"orbtr.platform:models.*", "-orbtr.platform:models.evict"},
			[]string{"orbtr.platform:models.*", "-orbtr.platform:models.EVICT"},
		},
		{
			"a grant missing its action refuses the set",
			[]string{"orbtr.platform:models.load", "orbtr.platform:training.submit"},
			[]string{"orbtr.platform:models.load", "orbtr.platform:training"},
		},
		{
			"another realm's malformed grant refuses the set too",
			[]string{"orbtr.platform:models.load", "orbtr.ai:inference.invoke"},
			[]string{"orbtr.platform:models.load", "orbtr.ai:inference"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !az.HasCapability(principalWith(t, c.valid...), required) {
				t.Fatalf("the well-formed set %v must admit %q", c.valid, required)
			}
			if az.HasCapability(principalWith(t, c.spoiled...), required) {
				t.Fatalf("the set %v holds a malformed grant and must be refused whole", c.spoiled)
			}
		})
	}
}

// The dotted vocabulary is not this judge's: a scope string, including a dotted deny, is no
// element of the capability set and neither admits nor refuses anything here.
func TestDirectCapabilitiesLeavesTheDottedVocabularyToItsOwnJudge(t *testing.T) {
	az := DirectCapabilities(platformRealm)
	required := "orbtr.platform:models.load"
	for _, grants := range [][]string{
		{"orbtr.platform.models.load", "orbtr.platform:models.load"},
		{"-orbtr.platform.models.load", "orbtr.platform:models.load"},
		{"orbtr.platform.models.*", "orbtr.platform:models.load"},
	} {
		if !az.HasCapability(principalWith(t, grants...), required) {
			t.Fatalf("a dotted scope string beside a held capability must not refuse it: %v", grants)
		}
	}
	if az.HasCapability(principalWith(t, "orbtr.platform.models.load"), required) {
		t.Fatal("a dotted scope string confers no capability on its own")
	}
}

// warrant's per-set count limit reaches this judge: a set at the limit is read and one past
// it is refused whole.
func TestDirectCapabilitiesAppliesTheSetCountLimit(t *testing.T) {
	az := DirectCapabilities(platformRealm)
	required := "orbtr.platform:models.load"

	atLimit := append(grantsOf(warrant.MaxCapabilitiesPerSet-1), required)
	if !az.HasCapability(principalWith(t, atLimit...), required) {
		t.Fatal("a held set at warrant.MaxCapabilitiesPerSet must be read")
	}
	past := append(grantsOf(warrant.MaxCapabilitiesPerSet), required)
	if az.HasCapability(principalWith(t, past...), required) {
		t.Fatal("a held set past warrant.MaxCapabilitiesPerSet must be refused whole")
	}
}
