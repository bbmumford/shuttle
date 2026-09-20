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
// weft is stamped only on the sealed receive path (WithAuthenticatedPrincipal,
// where the principal survived the transport-axis forge gate). loom lifts no
// identity from a request that arrives without a sealed principal, so
// weft.ExtractScopes is sealed-derived by construction: an authorization input
// that cannot be self-declared over the wire.
//
// It is product-agnostic (loom + weft only) and holds no carrier of its own:
// the product-specific stamp lives in the inner validator, whose ctx shuttle
// builds the weft stamp onto so both survive (dual-stamp on the sealed path).
// shuttle carries no transport-axis opinion either — the pin is inner's call.
package shuttle

import (
	"context"
	"errors"

	"github.com/bbmumford/loom/pkg/rpc/scope"
	"github.com/bbmumford/loom/ports"
	"github.com/bbmumford/weft"
)

// weftOrigin is the auth-type shuttle records on the weft carrier for a
// mesh-received principal. It is weft's own constant rather than a literal of
// shuttle's, because the inner stamper writes the same value onto a different
// carrier and a reader comparing either against a handler's admitted set does it
// by exact string match — two private spellings of one wire value agree only
// while nobody edits one of them.
const weftOrigin = weft.AuthTypeMesh

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

// WithPartitionID forwards to inner; the partition context key is inner's to own.
func (v weftStamping) WithPartitionID(ctx context.Context, partitionID string) context.Context {
	return v.inner.WithPartitionID(ctx, partitionID)
}

// AdmitPrincipal delegates to inner and admits nothing on its own. loom refuses
// every mesh principal when the validator implements no admitter ("a mesh
// principal requires a consumer principal admitter"); admitting here would flip
// that deny into an admit merely by wrapping. When inner has no admitter this
// refuses, so wrapping preserves loom's fail-closed exactly.
func (v weftStamping) AdmitPrincipal(ctx context.Context, transportPartition string, principal scope.AuthenticatedPrincipal) error {
	if admitter, ok := v.inner.(ports.PrincipalAdmitter); ok {
		return admitter.AdmitPrincipal(ctx, transportPartition, principal)
	}
	return errNoInnerAdmitter
}

// errNoInnerAdmitter is AdmitPrincipal's refusal when the wrapped validator
// implements no admitter.
var errNoInnerAdmitter = errors.New("the wrapped validator implements no principal admitter")

// WithAuthenticatedPrincipal (loom node/rpc.go receive path) delegates to inner's
// stamp first, then stamps weft onto the ctx inner RETURNED — building on inner's
// ctx so inner's carrier stamp survives (dual-stamp). Subject and scopes are read
// from the sealed principal, never re-derived. The loom RPC server calls this
// only after AdmitPrincipal has accepted the principal.
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
// validator (rpc.go: PrincipalAdmitter, AuthenticatedPrincipalStamper;
// executor: ExecutionPrincipalReader, PartitionPrincipalReader). A future edit
// that drops one fails the BUILD rather than silently disabling that gate — the
// only failure mode that matters, since a dropped extension has no runtime error,
// only a feature that quietly stops.
var (
	_ ports.AuthValidator                 = weftStamping{}
	_ ports.PrincipalAdmitter             = weftStamping{}
	_ ports.AuthenticatedPrincipalStamper = weftStamping{}
	_ ports.ExecutionPrincipalReader      = weftStamping{}
	_ ports.PartitionPrincipalReader      = weftStamping{}
)
