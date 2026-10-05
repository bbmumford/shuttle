/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package shuttle

import (
	"github.com/bbmumford/loom/pkg/rpc/scope"
	"github.com/bbmumford/warrant"
)

// DirectCapabilities returns a loom scope.Authorizer that confers a capability
// of realm only when the sealed principal's own grants, read as warrant
// capabilities of that same realm, allow it. It is the judge for authority
// that is minted onto a principal directly (platform-plane grants), as opposed
// to capabilities derived from a scope vocabulary.
//
// It is realm-closed in both directions: a required capability outside realm
// is refused, and grants outside realm are ignored, so no other realm's grant
// can satisfy or spoil a requirement here. A grant naming a realm before a colon
// is a capability and must parse: one that does not refuses the whole held set
// and with it every requirement, because the element that does not parse may be
// a deny and skipping it would confer what it withholds
// (warrant.ParseGrantSet). A grant with no colon is a dotted scope string, which
// another judge of the same policy reads through warrant.ScopeConversion, so it
// is no element of this set. Matching, terminal-"*" subsumption and deny
// precedence are warrant.CapabilitySet.Allows'.
//
// loom's registries call it through scope.NewPolicy(DirectCapabilities(realm))
// for operations that declare scope.Capability(...). Grants cross the mesh as
// the sending node wrote them, so the rule that a caller who must not hold a
// capability does not hold it is enforced where that caller's principal is
// minted, not here.
func DirectCapabilities(realm string) scope.Authorizer {
	return directCapabilities{realm: realm}
}

type directCapabilities struct{ realm string }

func (d directCapabilities) HasCapability(principal scope.AuthenticatedPrincipal, capability string) bool {
	required, err := warrant.ParseCapability(capability)
	if err != nil || required.IsDeny() || required.Realm() != d.realm {
		return false
	}
	held, err := warrant.ParseGrantSet(principal.Scopes(), d.realm)
	if err != nil {
		return false
	}
	return held.Allows(required)
}

var _ scope.Authorizer = directCapabilities{}
