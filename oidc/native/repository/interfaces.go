package repository

import (
	"context"
	"errors"

	"github.com/foomo/gosso/oidc/native/repository/store"
)

// ErrNotFound is returned for an unknown code or session.
var ErrNotFound = errors.New("native: not found")

// ErrConflict is returned by Session.Rotate when the stored refresh hash no
// longer equals the expected one, or the session is gone.
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
		// Rotate replaces the session iff its stored RefreshHash equals
		// expectedHash, so concurrent refreshes cannot both win; otherwise,
		// or if the session is gone, ErrConflict.
		Rotate(ctx context.Context, s store.Session, expectedHash string) error
		// Delete removes a session. Deleting a missing one is not an error.
		Delete(ctx context.Context, id string) error
	}
)
