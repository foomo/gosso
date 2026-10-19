package native

import (
	"context"
	"errors"
	"maps"
	"slices"
)

// ErrNotFound is returned for an unknown code or session.
var ErrNotFound = errors.New("native: not found")

// ErrConflict is returned by RotateSession when the stored refresh hash no
// longer equals the expected one, or the session is gone.
var ErrConflict = errors.New("native: conflict")

// Store persists codes and refresh sessions. Implementations must not
// filter by ExpiresAt: the broker checks expiry itself, and TTL indexes
// are garbage collection only. Returned values must not share maps or
// slices with stored ones.
type Store interface {
	// PutCode stores a pending code.
	PutCode(ctx context.Context, c Code) error
	// TakeCode atomically finds and deletes the code with the given hash;
	// ErrNotFound if there is none.
	TakeCode(ctx context.Context, hash string) (Code, error)
	// CreateSession stores a new session.
	CreateSession(ctx context.Context, s Session) error
	// GetSession loads a session; ErrNotFound if there is none.
	GetSession(ctx context.Context, id string) (Session, error)
	// RotateSession replaces the session iff its stored RefreshHash equals
	// expectedHash, so concurrent refreshes cannot both win; otherwise, or
	// if the session is gone, ErrConflict.
	RotateSession(ctx context.Context, s Session, expectedHash string) error
	// DeleteSession removes a session. Deleting a missing one is not an
	// error.
	DeleteSession(ctx context.Context, id string) error
}

// cloneGroups copies groups; nil and empty both become nil.
func cloneGroups(g []string) []string {
	if len(g) == 0 {
		return nil
	}

	return slices.Clone(g)
}

func cloneAttributes(a Attributes) Attributes {
	if a == nil {
		return nil
	}

	return maps.Clone(a)
}

func cloneCode(c Code) Code {
	c.Subject.Groups = cloneGroups(c.Subject.Groups)
	c.Attributes = cloneAttributes(c.Attributes)
	c.IDPRefreshToken.Ciphertext = slices.Clone(c.IDPRefreshToken.Ciphertext)

	return c
}

func cloneSession(s Session) Session {
	s.Subject.Groups = cloneGroups(s.Subject.Groups)
	s.Attributes = cloneAttributes(s.Attributes)
	s.IDPRefreshToken.Ciphertext = slices.Clone(s.IDPRefreshToken.Ciphertext)

	return s
}
