/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */

// Package shuttle carries a loom-sealed identity into the weft carrier on the
// mesh receive path. A shuttle carries the weft thread through the loom; this
// module carries the loom-sealed principal into weft.
//
// WeftStamping decorates any ports.AuthValidator: it forwards every seam the
// loom RPC server and executor assert on a validator to the inner validator
// unchanged, and stamps the weft carrier (weft.SetAuthContext) from the SEALED
// principal — and only from it. Post-seal gates that read weft.ExtractScopes
// then see the caller's real scopes, which over the mesh they otherwise never
// do (the product validator stamps its own carrier, not weft).
//
// weft is stamped ONLY on the sealed receive path (WithAuthenticatedPrincipal,
// where the principal survived the transport-axis forge gate). The wire-identity
// path (WithWireIdentity) reads its subject and scopes from the mutable request
// map with that gate skipped, so shuttle delegates that branch to inner but
// stamps NO weft from it — making weft.ExtractScopes structurally sealed-derived,
// an authorization input that cannot be self-declared over the wire.
//
// It is product-agnostic (loom + weft only) and holds no carrier of its own:
// the product-specific stamp lives in the inner validator, whose ctx shuttle
// builds the weft stamp onto so both survive (dual-stamp on the sealed path).
// shuttle carries no transport-axis opinion either — the pin is inner's call.
package shuttle

import (
	"context"

	"github.com/bbmumford/loom/pkg/rpc/scope"
	"github.com/bbmumford/loom/ports"
	"github.com/bbmumford/weft"
)

// weftOrigin is the auth-type shuttle records on the weft carrier for a
// mesh-received principal, matching the inner loom stamper's "mesh" origin so a
// weft reader cannot tell which stamp wrote it.
const weftOrigin = "mesh"

// weftStamping decorates inner so the mesh receive path also stamps weft. inner
// is the product's own validator (e.g. helpers.LoomValidator); shuttle never
// replaces its behaviour, only adds the weft stamp alongside it.
type weftStamping struct {
	inner ports.AuthValidator
}

// WeftStamping wraps inner so a received, transport-pinned principal is stamped
// into the weft carrier in addition to whatever inner stamps. Adoption:
// Spec.AuthValidator = shuttle.WeftStamping(<product base validator>).
func WeftStamping(inner ports.AuthValidator) ports.AuthValidator {
	return weftStamping{inner: inner}
}

// ValidateExecutionAuth forwards to inner; shuttle adds no authorization policy.
func (v weftStamping) ValidateExecutionAuth(ctx context.Context, h ports.SecureHandler) error {
	return v.inner.ValidateExecutionAuth(ctx, h)
}

// WithTenantID forwards to inner; the tenant context key is inner's to own.
func (v weftStamping) WithTenantID(ctx context.Context, tenantID string) context.Context {
	return v.inner.WithTenantID(ctx, tenantID)
}

// TransportPinnedAxis delegates to inner and carries no axis of its own. Two
// reasons a hardcoded axis would be wrong: (1) if inner pins a different axis,
// shuttle would make the RPC server reconcile an axis the product did not
// choose; (2) if inner does not pin at all, loom refuses every mesh principal
// ("mesh principal requires a consumer transport-axis pin") — returning a real
// axis here would flip that deny into an admit merely by wrapping. Returning ""
// when inner does not pin preserves loom's pre-wrap fail-closed exactly.
func (v weftStamping) TransportPinnedAxis() string {
	if pinner, ok := v.inner.(ports.TransportAxisPin); ok {
		return pinner.TransportPinnedAxis()
	}
	return ""
}

// WithAuthenticatedPrincipal (loom node/rpc.go receive path) delegates to inner's
// stamp first, then stamps weft onto the ctx inner RETURNED — building on inner's
// ctx so inner's carrier stamp survives (dual-stamp). Subject and scopes are read
// from the sealed principal, never re-derived. The loom RPC server calls this
// only after the transport-axis forge gate has passed, so the principal is
// already reconciled to the transport tenant.
func (v weftStamping) WithAuthenticatedPrincipal(ctx context.Context, principal scope.AuthenticatedPrincipal) context.Context {
	if stamper, ok := v.inner.(ports.AuthenticatedPrincipalStamper); ok {
		ctx = stamper.WithAuthenticatedPrincipal(ctx, principal)
	}
	id := principal.Identity()
	// Defence-in-depth on the sealed path: loom does not validate Subject, so a sealed
	// principal could carry an empty one, and weft.SetAuthContext marks authenticated
	// unconditionally. Never mark weft authenticated with no subject (weft's own session
	// stamper skips an empty UserID; match it). inner's carrier stamp above stays
	// unconditional, so shuttle changes nothing about the existing carrier.
	if id.Subject == "" {
		return ctx
	}
	return weft.SetAuthContext(ctx, id.Subject, principal.Scopes(), weftOrigin)
}

// WithWireIdentity (loom node/rpc.go wire-identity receive path) delegates to
// inner's stamp first, then stamps weft onto the returned ctx — the same
// dual-stamp on the wire-identity path so no receive route leaves weft unstamped.
func (v weftStamping) WithWireIdentity(ctx context.Context, userID string, scopes []string) context.Context {
	// The wire-identity branch reads userID and scopes from the mutable request map
	// with the transport-axis forge gate skipped (loom rpc.go, the !typedPrincipal
	// path), so both values are self-declarable and NOT sealed. Delegate to inner —
	// its carrier behaviour is byte-identical to today — but stamp NOTHING on weft:
	// weft is populated only from the sealed principal (WithAuthenticatedPrincipal).
	// Populating it here would let a peer that omits the sealed principal put
	// self-declared scopes into the authorization input warrantmesh / RequireScope read.
	if stamper, ok := v.inner.(ports.ScopeStamper); ok {
		return stamper.WithWireIdentity(ctx, userID, scopes)
	}
	return ctx
}

// ExecutionPrincipal (executor path) forwards to inner when inner reads one, and
// otherwise reports absence exactly as an unwrapped non-reader would — wrapping
// must not invent an execution principal.
func (v weftStamping) ExecutionPrincipal(ctx context.Context) (ports.ExecutionPrincipal, bool) {
	if reader, ok := v.inner.(ports.ExecutionPrincipalReader); ok {
		return reader.ExecutionPrincipal(ctx)
	}
	return nil, false
}

// ExecutionPartitionID (executor path) forwards to inner when inner reads one,
// and otherwise reports absence exactly as an unwrapped non-reader would.
func (v weftStamping) ExecutionPartitionID(ctx context.Context) (partitionID string, ok bool) {
	if reader, ok := v.inner.(ports.PartitionPrincipalReader); ok {
		return reader.ExecutionPartitionID(ctx)
	}
	return "", false
}

// Compile-time proof the decorator re-exposes every seam loom asserts on a
// validator (rpc.go: ScopeStamper, TransportAxisPin, AuthenticatedPrincipalStamper;
// executor: ExecutionPrincipalReader, PartitionPrincipalReader). A future edit
// that drops one fails the BUILD rather than silently disabling that gate — the
// only failure mode that matters, since a dropped extension has no runtime error,
// only a feature that quietly stops.
var (
	_ ports.AuthValidator                 = weftStamping{}
	_ ports.TransportAxisPin              = weftStamping{}
	_ ports.AuthenticatedPrincipalStamper = weftStamping{}
	_ ports.ScopeStamper                  = weftStamping{}
	_ ports.ExecutionPrincipalReader      = weftStamping{}
	_ ports.PartitionPrincipalReader      = weftStamping{}
)
