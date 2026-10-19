package native

import (
	"context"
	"errors"
	"sync/atomic"
)

var errStore = errors.New("store unavailable")

// faultyStore fails the RotateSession call numbered failAt (1-based) once.
type faultyStore struct {
	*MemoryStore

	failAt int32
	calls  atomic.Int32
}

func (s *faultyStore) RotateSession(ctx context.Context, sess Session, expectedHash string) error {
	if s.calls.Add(1) == s.failAt {
		return errStore
	}

	return s.MemoryStore.RotateSession(ctx, sess, expectedHash)
}

// ctxStore honours context cancellation like a networked store does.
type ctxStore struct {
	*MemoryStore
}

func (s ctxStore) GetSession(ctx context.Context, id string) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}

	return s.MemoryStore.GetSession(ctx, id)
}

func (s ctxStore) RotateSession(ctx context.Context, sess Session, expectedHash string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return s.MemoryStore.RotateSession(ctx, sess, expectedHash)
}

func (s ctxStore) DeleteSession(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	return s.MemoryStore.DeleteSession(ctx, id)
}
