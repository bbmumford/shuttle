package shuttle

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bbmumford/loom/pkg/rpc/scope"
	"github.com/bbmumford/weft"
)

// serveIngress runs one request through Ingress and returns the context the
// downstream handler saw, which is the only place a stamp is observable.
func serveIngress(t *testing.T, cfg IngressConfig) context.Context {
	t.Helper()
	var seen context.Context
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Context()
	})
	Ingress(cfg)(next).ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/", nil),
	)
	if seen == nil {
		t.Fatal("Ingress did not call the next handler")
	}
	return seen
}

// readerOf returns a CredentialReader that always proves identity.
func readerOf(identity ProvedIdentity, ok bool) CredentialReader {
	return CredentialReaderFunc(func(*http.Request) (ProvedIdentity, bool) {
		return identity, ok
	})
}

// assertUnstamped is the fail-closed expectation: neither carrier names a
// caller, so the presence policy has nothing to admit at the handler.
func assertUnstamped(t *testing.T, ctx context.Context, why string) {
	t.Helper()
	if _, ok := scope.AuthenticatedPrincipalFromContext(ctx); ok {
		t.Fatalf("%s: a principal was stamped; want none", why)
	}
	if weft.IsAuthenticated(ctx) {
		t.Fatalf("%s: weft marked the request authenticated; want unauthenticated", why)
	}
}

func TestIngressStampsProvedCredential(t *testing.T) {
	ctx := serveIngress(t, IngressConfig{
		Reader: readerOf(ProvedIdentity{
			Subject:   "usr_1",
			Partition: "acme",
			Grants:    []string{"orbtr.ai:model.read"},
		}, true),
	})

	principal, ok := scope.AuthenticatedPrincipalFromContext(ctx)
	if !ok {
		t.Fatal("a proved credential must stamp a principal")
	}
	identity := principal.Identity()
	if identity.Subject != "usr_1" {
		t.Fatalf("subject = %q, want usr_1", identity.Subject)
	}
	if identity.Partition() != "acme" {
		t.Fatalf("partition = %q, want acme", identity.Partition())
	}
	if got := principal.Scopes(); len(got) != 1 || got[0] != "orbtr.ai:model.read" {
		t.Fatalf("grants = %v, want [orbtr.ai:model.read]", got)
	}

	// The weft carrier must agree with the seal, because post-seal gates read it
	// instead of the principal.
	if !weft.IsAuthenticated(ctx) {
		t.Fatal("weft must mark a stamped request authenticated")
	}
	if got := weft.ExtractUserID(ctx); got != "usr_1" {
		t.Fatalf("weft user = %q, want usr_1", got)
	}
	if got := weft.ExtractScopes(ctx); len(got) != 1 || got[0] != "orbtr.ai:model.read" {
		t.Fatalf("weft scopes = %v, want [orbtr.ai:model.read]", got)
	}
	if got := weft.GetAuthType(ctx); got != weft.AuthTypeSession {
		t.Fatalf("weft auth type = %q, want %q", got, weft.AuthTypeSession)
	}
}

func TestIngressLeavesUnprovedRequestsUnstamped(t *testing.T) {
	full := ProvedIdentity{Subject: "usr_1", Partition: "acme"}

	assertUnstamped(t, serveIngress(t, IngressConfig{Reader: readerOf(full, false)}),
		"a reader reporting no credential")
	assertUnstamped(t, serveIngress(t, IngressConfig{
		Reader: readerOf(ProvedIdentity{Subject: "", Partition: "acme"}, true),
	}), "a credential naming no subject")
	assertUnstamped(t, serveIngress(t, IngressConfig{
		Reader: readerOf(ProvedIdentity{Subject: "usr_1", Partition: ""}, true),
	}), "a credential carrying no partition")
	assertUnstamped(t, serveIngress(t, IngressConfig{}),
		"no reader configured")
	assertUnstamped(t, serveIngress(t, IngressConfig{
		Reader: readerOf(full, true), AuthType: weft.AuthTypeUnknown,
	}), "the unknown auth-type sentinel offered as a credential")
}

// A grant loom would refuse must leave the request unstamped rather than
// degrade to a grant-less principal: scope.PrincipalForEnforcement treats a
// grant-less principal as a valid partition-bearing caller, so degrading would
// admit a partition read the credential never proved.
func TestIngressRefusesNonCanonicalGrant(t *testing.T) {
	ctx := serveIngress(t, IngressConfig{
		Reader: readerOf(ProvedIdentity{
			Subject:   "usr_1",
			Partition: "acme",
			Grants:    []string{" orbtr.ai:model.read"},
		}, true),
	})
	assertUnstamped(t, ctx, "a non-canonical grant")
}

func TestIngressRecordsTheConfiguredAuthType(t *testing.T) {
	ctx := serveIngress(t, IngressConfig{
		Reader:   readerOf(ProvedIdentity{Subject: "svc", Partition: "orbtr"}, true),
		AuthType: weft.AuthTypeAPIKey,
	})
	if got := weft.GetAuthType(ctx); got != weft.AuthTypeAPIKey {
		t.Fatalf("weft auth type = %q, want %q", got, weft.AuthTypeAPIKey)
	}
}

// The reader keeps its slice; the stamp must not alias it, or a reader that
// pools or reuses its grant buffer would rewrite authority already in flight.
func TestIngressSealsGrantsAgainstReaderMutation(t *testing.T) {
	grants := []string{"orbtr.ai:model.read"}
	ctx := serveIngress(t, IngressConfig{
		Reader: readerOf(ProvedIdentity{Subject: "usr_1", Partition: "acme", Grants: grants}, true),
	})
	grants[0] = "orbtr.platform:everything.do"

	principal, ok := scope.AuthenticatedPrincipalFromContext(ctx)
	if !ok {
		t.Fatal("a proved credential must stamp a principal")
	}
	if got := principal.Scopes(); got[0] != "orbtr.ai:model.read" {
		t.Fatalf("sealed grant = %q, want the value proved at stamp time", got[0])
	}
	if got := weft.ExtractScopes(ctx); got[0] != "orbtr.ai:model.read" {
		t.Fatalf("weft scope = %q, want the value proved at stamp time", got[0])
	}
}

// The partition reaches the admitter as the principal's own, so an Ingress
// stamp and a mesh-received principal are admitted by the one rule.
func TestIngressStampFeedsTheAdmitter(t *testing.T) {
	ctx := serveIngress(t, IngressConfig{
		Reader: readerOf(ProvedIdentity{Subject: "usr_1", Partition: "acme"}, true),
	})
	principal, ok := scope.AuthenticatedPrincipalFromContext(ctx)
	if !ok {
		t.Fatal("a proved credential must stamp a principal")
	}
	admit := MembershipAdmitter{IsMember: func(_ context.Context, subject, partition string) (bool, error) {
		return subject == "usr_1" && partition == "acme", nil
	}}
	if err := admit.AdmitPrincipal(ctx, "orbtr", principal); err != nil {
		t.Fatalf("an Ingress-stamped principal must be admissible: %v", err)
	}
}

// TestIngressSealReceivesTheProvedIdentity covers the reason Seal exists: the
// loom principal carries subject, partition and grants, so a field it has no room
// for — SessionID — reaches a consumer only through this hook. Asserting the
// session VALUE rather than that Seal ran is what distinguishes a hook wired to
// the proved identity from one handed an empty struct.
func TestIngressSealReceivesTheProvedIdentity(t *testing.T) {
	var seen ProvedIdentity
	serveIngress(t, IngressConfig{
		Reader: readerOf(ProvedIdentity{
			Subject: "usr_1", Partition: "acme", SessionID: "sess_abc",
		}, true),
		Seal: func(ctx context.Context, proved ProvedIdentity) context.Context {
			seen = proved
			return ctx
		},
	})

	if seen.SessionID != "sess_abc" {
		t.Fatalf("Seal saw SessionID %q, want the one the reader proved", seen.SessionID)
	}
	if seen.Subject != "usr_1" || seen.Partition != "acme" {
		t.Fatalf("Seal saw %+v, want the full proved identity", seen)
	}
}

// TestIngressSealDoesNotRunOnAnUnprovedRequest pins the property that makes this
// hook safe to add: it cannot turn an unauthenticated request into a decorated
// one. A consumer stamping its own carrier here must never see a request the
// loom and weft seals above declined to stamp.
func TestIngressSealDoesNotRunOnAnUnprovedRequest(t *testing.T) {
	ran := false
	record := func(ctx context.Context, _ ProvedIdentity) context.Context {
		ran = true
		return ctx
	}

	serveIngress(t, IngressConfig{
		Reader: readerOf(ProvedIdentity{Subject: "usr_1", Partition: "acme"}, false),
		Seal:   record,
	})
	if ran {
		t.Fatal("Seal ran for a reader reporting no credential")
	}

	serveIngress(t, IngressConfig{
		Reader: readerOf(ProvedIdentity{Subject: "usr_1"}, true), // no partition
		Seal:   record,
	})
	if ran {
		t.Fatal("Seal ran for an identity missing its partition")
	}
}

// TestIngressSealReturningNilKeepsTheSeals is the guard on the guard. A decorator
// that returns nil would otherwise blank the context, discarding the loom and
// weft stamps this hook exists to EXTEND — so a request that proved would reach
// the handler less authenticated than one that did not.
func TestIngressSealReturningNilKeepsTheSeals(t *testing.T) {
	ctx := serveIngress(t, IngressConfig{
		Reader: readerOf(ProvedIdentity{Subject: "usr_1", Partition: "acme"}, true),
		Seal:   func(context.Context, ProvedIdentity) context.Context { return nil },
	})

	if _, ok := scope.AuthenticatedPrincipalFromContext(ctx); !ok {
		t.Fatal("a nil-returning Seal discarded the loom principal")
	}
}
