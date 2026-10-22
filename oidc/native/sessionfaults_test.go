package native

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/foomo/gosso/oidc/native/repository"
	"github.com/foomo/gosso/oidc/native/repository/store"
)

var errStore = errors.New("store unavailable")

// faultySessions fails the Rotate call numbered failAt (1-based) once.
type faultySessions struct {
	repository.Session

	failAt int32
	calls  atomic.Int32
}

func (s *faultySessions) Rotate(ctx context.Context, sess store.Session) error {
	if s.calls.Add(1) == s.failAt {
		return errStore
	}

	return s.Session.Rotate(ctx, sess)
}

// leaseThief hands the lease to another refresh right after the claim, as
// if this refresh's lease had expired and been taken over.
type leaseThief struct {
	repository.Session

	stolen atomic.Bool
}

func (s *leaseThief) Rotate(ctx context.Context, sess store.Session) error {
	if err := s.Session.Rotate(ctx, sess); err != nil {
		return err
	}

	if sess.RefreshLease == "" || !s.stolen.CompareAndSwap(false, true) {
		return nil
	}

	sess.Version++
	sess.RefreshLease = "thief"

	return s.Session.Rotate(ctx, sess)
}
