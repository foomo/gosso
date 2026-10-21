package repository

import (
	"context"
	"errors"

	"github.com/foomo/gosso/oidc/native/repository/store"
)

// ErrNotFound is returned for an unknown code or session.
var ErrNotFound = errors.New("native: not found")

// ErrConflict is returned by Session.Rotate when the stored version no
// longer equals the given one, or the session is gone.
var ErrConflict = errors.New("native: conflict")

type (
	// Code persists pending one-time codes. Implementations must not filter
	// by ExpiresAt: the broker checks expiry itself, and TTL indexes are
	// garbage collection only.
	Code interface {
		// Put stores a pending code.
		Put(ctx context.Context, c store.Code) error
		// Take atomically finds and deletes the code with the given hash;
		// ErrNotFound if there is none.
		Take(ctx context.Context, hash string) (store.Code, error)
	}
	// Session persists refresh sessions, under the same rules as Code.
	Session interface {
		// Create stores a new session.
		Create(ctx context.Context, s store.Session) error
		// Get loads a session; ErrNotFound if there is none.
		Get(ctx context.Context, id string) (store.Session, error)
		// Rotate replaces the session with s iff its stored Version equals
		// s.Version, and stores it with Version+1, so concurrent writers
		// cannot both win; otherwise, or if the session is gone,
		// ErrConflict. The caller's s keeps the old Version: increment it
		// before writing the same copy again.
		Rotate(ctx context.Context, s store.Session) error
		// Delete removes a session. Deleting a missing one is not an error.
		Delete(ctx context.Context, id string) error
	}
)
