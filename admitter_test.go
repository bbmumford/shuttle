package shuttle

import (
	"context"
	"errors"
	"testing"

	"github.com/bbmumford/loom/pkg/rpc/scope"
)

func principalIn(t *testing.T, subject, partition string) scope.AuthenticatedPrincipal {
	t.Helper()
	p, err := scope.NewAuthenticatedPrincipal(scope.NewIdentity(subject, partition), nil)
	if err != nil {
		t.Fatalf("mint principal: %v", err)
	}
	return p
}

func TestMembershipAdmitter(t *testing.T) {
	ctx := context.Background()
	var asked [][2]string
	members := map[[2]string]bool{{"usr_1", "acme"}: true}
	check := func(_ context.Context, subject, partition string) (bool, error) {
		asked = append(asked, [2]string{subject, partition})
		return members[[2]string{subject, partition}], nil
	}
	admit := MembershipAdmitter{IsMember: check}

	if err := admit.AdmitPrincipal(ctx, "orbtr", principalIn(t, "svc", "orbtr")); err != nil {
		t.Fatalf("a principal in the transport's own partition must be admitted: %v", err)
	}
	if len(asked) != 0 {
		t.Fatalf("the transport's own partition must not need a membership read; asked %v", asked)
	}
	if err := admit.AdmitPrincipal(ctx, "orbtr", principalIn(t, "usr_1", "acme")); err != nil {
		t.Fatalf("a member of the asserted partition must be admitted: %v", err)
	}
	if len(asked) != 1 || asked[0] != [2]string{"usr_1", "acme"} {
		t.Fatalf("membership read = %v, want the principal's subject and asserted partition", asked)
	}
	if err := admit.AdmitPrincipal(ctx, "orbtr", principalIn(t, "usr_1", "globex")); !errors.Is(err, ErrNotMember) {
		t.Fatalf("a subject asserted into a partition it is not in: err = %v, want ErrNotMember", err)
	}
	if err := admit.AdmitPrincipal(ctx, "orbtr", principalIn(t, "usr_1", "")); !errors.Is(err, ErrNoPartition) {
		t.Fatalf("a principal with no partition: err = %v, want ErrNoPartition", err)
	}
	if err := admit.AdmitPrincipal(ctx, "orbtr", principalIn(t, "", "acme")); !errors.Is(err, ErrNoSubject) {
		t.Fatalf("a principal naming no subject: err = %v, want ErrNoSubject", err)
	}
	if err := admit.AdmitPrincipal(ctx, "orbtr", principalIn(t, "", "orbtr")); !errors.Is(err, ErrNoSubject) {
		t.Fatalf("a subjectless principal in the transport's own partition must still be refused: err = %v", err)
	}
	if err := (MembershipAdmitter{}).AdmitPrincipal(ctx, "orbtr", principalIn(t, "usr_1", "acme")); !errors.Is(err, ErrNoMembership) {
		t.Fatalf("no membership check configured: err = %v, want ErrNoMembership", err)
	}
	broken := MembershipAdmitter{IsMember: func(context.Context, string, string) (bool, error) {
		return true, errors.New("graph offline")
	}}
	if err := broken.AdmitPrincipal(ctx, "orbtr", principalIn(t, "usr_1", "acme")); !errors.Is(err, ErrMembershipUnread) {
		t.Fatalf("an unreadable membership must refuse even when the check also says true: err = %v", err)
	}
}

// The rule does not bend for service code. A service principal that names a
// partition it does not belong to is refused exactly like any other principal,
// whatever grants it carries and whichever transport it arrived on — service
// code that acts on another partition carries that partition as a request
// field, not as the partition it claims to belong to.
func TestMembershipAdmitter_ServicePrincipalGetsNoShortcut(t *testing.T) {
	ctx := context.Background()
	admit := MembershipAdmitter{IsMember: func(_ context.Context, subject, partition string) (bool, error) {
		return subject == "svc_placer" && partition == "orbtr", nil
	}}
	svc, err := scope.NewAuthenticatedPrincipal(
		scope.NewIdentity("svc_placer", "acme"),
		[]string{"orbtr.platform:model_placement.place"},
	)
	if err != nil {
		t.Fatalf("mint service principal: %v", err)
	}
	if err := admit.AdmitPrincipal(ctx, "orbtr", svc); !errors.Is(err, ErrNotMember) {
		t.Fatalf("a service principal naming a partition it is not in: err = %v, want ErrNotMember", err)
	}
	// The same service, naming the partition it does belong to, is admitted.
	home, err := scope.NewAuthenticatedPrincipal(
		scope.NewIdentity("svc_placer", "orbtr"),
		[]string{"orbtr.platform:model_placement.place"},
	)
	if err != nil {
		t.Fatalf("mint service principal: %v", err)
	}
	if err := admit.AdmitPrincipal(ctx, "acme", home); err != nil {
		t.Fatalf("a service principal in its own partition must be admitted over any transport: %v", err)
	}
}
