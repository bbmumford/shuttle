/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */

package shuttle

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/bbmumford/loom/pkg/rpc/scope"
	"github.com/bbmumford/loom/ports"
	"github.com/bbmumford/weft"
)

// --- context markers the inner stubs stamp, so a test can prove the weft stamp
// was built on the ctx inner RETURNED (dual-stamp), not on the original ctx
// (which would discard inner's stamp — the silent constraint-3 violation). ---

type principalMarkerKey struct{}
type partitionMarkerKey struct{}

var errValidate = errors.New("inner validate sentinel")

// fullInner implements the base AuthValidator plus every optional seam loom
// asserts, recording each stamp as a ctx value and pinning a specific axis.
type fullInner struct{}

func (fullInner) ValidateExecutionAuth(ctx context.Context, h ports.SecureHandler) error {
	return errValidate
}
func (fullInner) WithPartitionID(ctx context.Context, partitionID string) context.Context {
	return context.WithValue(ctx, partitionMarkerKey{}, partitionID)
}
func (fullInner) AdmitPrincipal(context.Context, string, scope.AuthenticatedPrincipal) error {
	return errInnerRefused
}
func (fullInner) WithAuthenticatedPrincipal(ctx context.Context, p scope.AuthenticatedPrincipal) context.Context {
	return context.WithValue(ctx, principalMarkerKey{}, true)
}
func (fullInner) ExecutionPrincipal(ctx context.Context) (ports.ExecutionPrincipal, bool) {
	return stubExecPrincipal{}, true
}
func (fullInner) ExecutionPartitionID(ctx context.Context) (string, bool) {
	return "inner_partition", true
}

// bareInner implements ONLY the base AuthValidator — none of the optional seams.
// Wrapping it must not change what the optional seams do relative to leaving it
// unwrapped: admission must stay refused (fail-closed) and the readers absent.
type bareInner struct{}

func (bareInner) ValidateExecutionAuth(ctx context.Context, h ports.SecureHandler) error  { return nil }
func (bareInner) WithPartitionID(ctx context.Context, partitionID string) context.Context { return ctx }

type stubExecPrincipal struct{}

func (stubExecPrincipal) PartitionKey() ports.ExecutionPartitionKey {
	return ports.ExecutionPartitionKey{}
}
func (stubExecPrincipal) AuthorizeExecution(ctx context.Context) (context.Context, func(), error) {
	return ctx, func() {}, nil
}

func testPrincipal(t *testing.T, subject string, scopes ...string) scope.AuthenticatedPrincipal {
	t.Helper()
	id, err := scope.NewCompleteIdentity(subject,
		scope.ScopeValue{Name: scope.AxisTransportPinned, Value: "orbtr"})
	if err != nil {
		t.Fatalf("NewCompleteIdentity: %v", err)
	}
	p, err := scope.NewAuthenticatedPrincipal(id, scopes)
	if err != nil {
		t.Fatalf("NewAuthenticatedPrincipal: %v", err)
	}
	return p
}

// TestWeftStamping_AuthenticatedPrincipal_DualStamp: weft is stamped from the
// sealed principal AND inner's stamp survives (ctx chained). The specific-value
// weft assertions fail if the weft stamp is dropped; the inner-marker assertion
// fails if the weft stamp is built on the original ctx instead of inner's.
func TestWeftStamping_AuthenticatedPrincipal_DualStamp(t *testing.T) {
	scopes := []string{"orbtr.storage.blob.read", "orbtr.storage.token.mint"}
	p := testPrincipal(t, "usr_alice", scopes...)

	ctx := WeftStamping(fullInner{}).(ports.AuthenticatedPrincipalStamper).
		WithAuthenticatedPrincipal(context.Background(), p)

	// weft stamped from the SEALED subject (preserved, not re-derived) + scopes.
	if got := weft.ExtractUserID(ctx); got != "usr_alice" {
		t.Errorf("weft subject = %q, want the sealed subject usr_alice", got)
	}
	if got := weft.ExtractScopes(ctx); !reflect.DeepEqual(got, scopes) {
		t.Errorf("weft scopes = %v, want %v", got, scopes)
	}
	// inner's stamp survives ⇒ weft was built on the ctx inner returned (dual-stamp).
	if ctx.Value(principalMarkerKey{}) != true {
		t.Error("inner principal stamp discarded: weft was stamped on the original ctx, not inner's")
	}
}

// errInnerRefused is fullInner's admitter verdict, distinct from any error the
// decorator could produce on its own.
var errInnerRefused = errors.New("refused by the inner admitter")

// TestWeftStamping_AdmitterDelegation: shuttle carries no admission opinion.
// Wrapping an inner with an admitter returns that admitter's own verdict;
// wrapping an inner without one refuses, as loom does for an unwrapped
// validator with no admitter, rather than admitting merely by wrapping.
func TestWeftStamping_AdmitterDelegation(t *testing.T) {
	var principal scope.AuthenticatedPrincipal
	if err := WeftStamping(fullInner{}).(ports.PrincipalAdmitter).AdmitPrincipal(context.Background(), "orbtr", principal); !errors.Is(err, errInnerRefused) {
		t.Errorf("wrapping an inner admitter: err = %v, want the inner's own verdict", err)
	}
	if err := WeftStamping(bareInner{}).(ports.PrincipalAdmitter).AdmitPrincipal(context.Background(), "orbtr", principal); err == nil {
		t.Error("wrapping an inner with no admitter admitted a principal; it must refuse as an unwrapped validator would")
	}
}

// TestWeftStamping_ReaderTransparency: the executor-path readers forward inner's
// values, and report absence exactly as an unwrapped non-reader would — wrapping
// invents no execution principal or partition.
func TestWeftStamping_ReaderTransparency(t *testing.T) {
	full := WeftStamping(fullInner{})
	if id, ok := full.(ports.PartitionPrincipalReader).ExecutionPartitionID(context.Background()); !ok || id != "inner_partition" {
		t.Errorf("partition forward: got (%q,%v), want (inner_partition,true)", id, ok)
	}
	if _, ok := full.(ports.ExecutionPrincipalReader).ExecutionPrincipal(context.Background()); !ok {
		t.Error("execution principal forward: got ok=false, want true")
	}

	bare := WeftStamping(bareInner{})
	if id, ok := bare.(ports.PartitionPrincipalReader).ExecutionPartitionID(context.Background()); ok || id != "" {
		t.Errorf("partition absence: got (%q,%v), want (\"\",false) as an unwrapped non-reader", id, ok)
	}
	if p, ok := bare.(ports.ExecutionPrincipalReader).ExecutionPrincipal(context.Background()); ok || p != nil {
		t.Errorf("execution principal absence: got (%v,%v), want (nil,false)", p, ok)
	}
}

// TestWeftStamping_SealedEmptySubject_NoWeft is defence-in-depth on the SEALED
// path: loom does not validate Subject, so a sealed principal could carry an
// empty one, and weft.SetAuthContext marks authenticated unconditionally. shuttle
// must not mark weft authenticated with no subject even here. inner still delegated.
func TestWeftStamping_SealedEmptySubject_NoWeft(t *testing.T) {
	scopes := []string{"orbtr.storage.blob.read"}
	pEmpty := testPrincipal(t, "", scopes...)
	ctx := WeftStamping(fullInner{}).(ports.AuthenticatedPrincipalStamper).
		WithAuthenticatedPrincipal(context.Background(), pEmpty)

	if weft.IsAuthenticated(ctx) {
		t.Error("empty-subject sealed principal must NOT stamp weft as authenticated")
	}
	if got := weft.ExtractScopes(ctx); len(got) != 0 {
		t.Errorf("empty-subject sealed principal must not stamp scopes into weft, got %v", got)
	}
	if ctx.Value(principalMarkerKey{}) != true {
		t.Error("inner stamp must still run for an empty subject (delegation is unconditional)")
	}
}

// TestWeftStamping_ForwardsBaseAuth: the non-optional base methods forward to inner.
func TestWeftStamping_ForwardsBaseAuth(t *testing.T) {
	v := WeftStamping(fullInner{})
	if err := v.ValidateExecutionAuth(context.Background(), nil); !errors.Is(err, errValidate) {
		t.Errorf("ValidateExecutionAuth = %v, want inner sentinel", err)
	}
	ctx := v.WithPartitionID(context.Background(), "orbtr")
	if ctx.Value(partitionMarkerKey{}) != "orbtr" {
		t.Error("WithPartitionID did not forward to inner")
	}
}
