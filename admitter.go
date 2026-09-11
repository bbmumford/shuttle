package shuttle

import (
	"context"
	"errors"
	"fmt"

	"github.com/bbmumford/loom/pkg/rpc/scope"
	"github.com/bbmumford/loom/ports"
)

// MembershipFunc reports whether subject is a member of partition. A consumer
// backs it with its membership graph; an error means the answer could not be
// read, never that the subject is not a member.
type MembershipFunc func(ctx context.Context, subject, partition string) (bool, error)

// MembershipAdmitter is a ports.PrincipalAdmitter for principals that arrive
// from another node carrying the partition the sending node asserts. It admits
// a principal whose partition is the transport's own, and otherwise only one
// whose subject IsMember confirms belongs to the asserted partition. So a
// sending node can present a subject in any partition that subject belongs to,
// and in no other.
type MembershipAdmitter struct {
	// IsMember confirms a subject's membership of a partition other than the
	// transport's. Nil refuses every such principal.
	IsMember MembershipFunc
}

var _ ports.PrincipalAdmitter = MembershipAdmitter{}

// Refusals AdmitPrincipal returns; each is wrapped with the partition involved.
var (
	ErrNoPartition      = errors.New("shuttle: principal carries no partition")
	ErrNoMembership     = errors.New("shuttle: no membership check configured")
	ErrNotMember        = errors.New("shuttle: subject is not a member of the asserted partition")
	ErrMembershipUnread = errors.New("shuttle: membership could not be read")
)

// AdmitPrincipal admits principal over the transport established for
// transportPartition, or refuses it with an error naming why.
func (a MembershipAdmitter) AdmitPrincipal(ctx context.Context, transportPartition string, principal scope.AuthenticatedPrincipal) error {
	identity := principal.Identity()
	partition := identity.Partition()
	if partition == "" {
		return ErrNoPartition
	}
	if partition == transportPartition {
		return nil
	}
	if a.IsMember == nil {
		return fmt.Errorf("%w for partition %q", ErrNoMembership, partition)
	}
	member, err := a.IsMember(ctx, identity.Subject, partition)
	if err != nil {
		return fmt.Errorf("%w for partition %q: %v", ErrMembershipUnread, partition, err)
	}
	if !member {
		return fmt.Errorf("%w %q", ErrNotMember, partition)
	}
	return nil
}
