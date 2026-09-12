/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */

package shuttle

import (
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
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
