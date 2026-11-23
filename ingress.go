/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */

package shuttle

import (
	"context"
	"net/http"

	"github.com/bbmumford/loom/pkg/rpc/scope"
	"github.com/bbmumford/weft"
)

// ProvedIdentity is what an HTTP ingress established about a request before
// loom will carry it: the subject the credential belongs to, the opaque
// partition a store selector keys on, and the grants the credential confers.
//
// Every field is server-established — read back from the store that issued the
// credential, never lifted from the request. A tessera Session carries Subject
// and Partition; a census API key carries its capabilities. Ingress seals
// whatever it is given into the principal scope.AuthorizeRequirement judges, so
// a header or body field reaching one of these fields is a forged authority.
type ProvedIdentity struct {
	Subject   string
	Partition string
	Grants    []string

	// SessionID is the identifier of the session the credential was proved
	// through, for a consumer that must scope a record to one sitting rather than
	// to the subject — enrolling a device key against the session that authorised
	// it, so a later session cannot use the enrolment.
	//
	// Empty is a legitimate value, not a missing one: a credential with no session
	// behind it (an API key, a machine caller) has no sitting to name, and a
	// consumer that needs one must refuse an empty value rather than substitute
	// the subject. Subject identifies WHO; this identifies WHICH VISIT.
	SessionID string
}

// CredentialReader resolves the credential a request carries into the identity
// its issuer recorded. ok is false when the request carries no credential this
// reader recognises; that is not an error, and Ingress leaves such a request
// unstamped.
//
// The consumer implements it over its own session or key store — the only place
// that knows what proves a request — so shuttle depends on neither.
type CredentialReader interface {
	ReadCredential(r *http.Request) (identity ProvedIdentity, ok bool)
}

// CredentialReaderFunc adapts a plain func to CredentialReader.
type CredentialReaderFunc func(r *http.Request) (ProvedIdentity, bool)

// ReadCredential calls f.
func (f CredentialReaderFunc) ReadCredential(r *http.Request) (ProvedIdentity, bool) {
	return f(r)
}

// IngressConfig wires Ingress. A zero value stamps nothing: with no Reader
// there is no store to prove a request, and minting a principal without one
// asserts a verification that did not happen.
type IngressConfig struct {
	// Reader proves the request. nil leaves every request unstamped.
	Reader CredentialReader

	// AuthType is the weft auth-type label recording HOW the caller
	// authenticated; weft.AuthTypeSession when empty. weft.AuthTypeUnknown is
	// refused: weft reserves it for "nothing stamped a type", so accepting it
	// here would make weft.GetAuthType report an unstamped request as
	// authenticated.
	AuthType string

	// Seal, when non-nil, decorates the context after the loom and weft stamps,
	// receiving the proved identity in full — including the fields the loom
	// principal has no room for, such as SessionID.
	//
	// It exists because a consumer's own identity carrier is declared downstream
	// of this package and cannot be named here: shuttle depends on loom and weft
	// and on no consumer's types, which is what lets an application evolve its
	// carrier without a change reaching this module. The consumer supplies the one
	// function that knows both sides.
	//
	// It runs only on a request that proved, after the seals above, so it observes
	// the same identity they did and cannot cause a request to be treated as
	// authenticated that otherwise would not be. Returning the ctx unchanged is
	// valid; returning a nil ctx is ignored, because a decorator that drops the
	// context would discard the loom and weft stamps this function exists to
	// extend. nil stamps nothing extra, which is what a consumer needing only the
	// loom principal wants.
	Seal func(ctx context.Context, proved ProvedIdentity) context.Context
}

// Ingress is the HTTP arm of what WeftStamping does on the mesh receive path.
// It turns a proved credential into the sealed loom principal carrying the
// opaque partition, and stamps the weft carrier from that same seal, so a
// handler reached over HTTP and one reached over the mesh read the same
// authority from the same place.
//
// It attaches; it does not gate. A request with no credential, an incomplete
// one, or a non-canonical grant passes through with nothing stamped:
// scope.AuthenticatedPrincipalFromContext then reports none and the consumer's
// PresencePolicy denies at the handler, keeping the deny in one place rather
// than splitting it between here and enforcement.
//
// Subject and Partition must both be non-empty. weft.SetAuthContext marks a
// request authenticated unconditionally, so a subject-less stamp would mark one
// authenticated with nobody; and an identity with no partition satisfies only a
// ScopeNone handler, which enforces nothing anyway, while every partition-keyed
// selector denies it. Stamping either case buys no reach and costs the
// fail-closed read.
func Ingress(cfg IngressConfig) func(http.Handler) http.Handler {
	authType := cfg.AuthType
	if authType == "" {
		authType = weft.AuthTypeSession
	}
	// Resolved once at wiring time: a misconfigured Ingress must behave the same
	// on every request rather than depending on what a reader happens to return.
	stamps := cfg.Reader != nil && authType != weft.AuthTypeUnknown

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !stamps {
				next.ServeHTTP(w, r)
				return
			}
			proved, ok := cfg.Reader.ReadCredential(r)
			if !ok || proved.Subject == "" || proved.Partition == "" {
				next.ServeHTTP(w, r)
				return
			}
			principal, err := scope.NewAuthenticatedPrincipal(
				scope.NewIdentity(proved.Subject, proved.Partition),
				proved.Grants,
			)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			ctx := scope.WithAuthenticatedPrincipal(r.Context(), principal)
			// Read back through the principal's copying accessors rather than from
			// proved: a grant slice the reader retains then cannot alter what
			// weft.ExtractScopes reports after the stamp.
			ctx = weft.SetAuthContext(
				ctx,
				principal.Identity().Subject,
				principal.Scopes(),
				authType,
			)
			// After the seals above, so a decorator observes the identity they
			// sealed. A nil return is ignored rather than honoured: dropping the
			// context here would discard the loom and weft stamps this hook exists
			// to extend, and a request would reach the handler less authenticated
			// than the one that proved.
			if cfg.Seal != nil {
				if sealed := cfg.Seal(ctx, proved); sealed != nil {
					ctx = sealed
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
