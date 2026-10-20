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

func (s *faultySessions) Rotate(ctx context.Context, sess store.Session, expectedHash string) error {
	if s.calls.Add(1) == s.failAt {
		return errStore
	}

	return s.Session.Rotate(ctx, sess, expectedHash)
}
