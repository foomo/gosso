package store

import (
	"time"
)

// Session is a refresh session, one per logged-in app install.
//
// Refresh secrets are stored as base64url(SHA-256) hashes in three
// generations. A rotation moves the current generation to previous and
// the previous one to retired.
type Session struct {
	// ID is the random session ID, the first part of the refresh token.
	ID       string
	ClientID string
	// Version is incremented by every stored change; the session
	// repository's Rotate is a compare-and-swap on it.
	Version uint64
	// RefreshHashes are the current secrets: the one issued by the last
	// rotation plus those issued to concurrent duplicates in its grace
	// window. Each of them refreshes the session.
	RefreshHashes []string
	// PreviousRefreshHashes were current until RotatedAt and are accepted
	// for the rotation grace window after it.
	PreviousRefreshHashes []string
	RotatedAt             time.Time
	// RetiredRefreshHashes are older secrets, kept so that presenting one
	// is recognised as reuse.
	RetiredRefreshHashes []string
	// RefreshLease and RefreshLeaseUntil are set while one refresh holds
	// the session at the IdP; concurrent refreshes wait for it.
	RefreshLease      string
	RefreshLeaseUntil time.Time
	Subject           Subject
	Attributes        Attributes
	IDPRefreshToken   EncryptedToken
	CreatedAt         time.Time
	LastUsedAt        time.Time
	// ExpiresAt is the absolute end of the session.
	ExpiresAt time.Time
}
