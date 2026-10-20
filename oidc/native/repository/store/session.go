package store

import (
	"time"
)

// Session is a refresh session, one per logged-in app install.
type Session struct {
	// ID is the random session ID, the first part of the refresh token.
	ID       string
	ClientID string
	// RefreshHash is base64url(SHA-256) of the current refresh secret.
	RefreshHash string
	// PreviousRefreshHash and RotatedAt let the previous secret through
	// for the rotation grace window. Grace hits rotate RefreshHash but
	// leave both as they are.
	PreviousRefreshHash string
	RotatedAt           time.Time
	Subject             Subject
	Attributes          Attributes
	IDPRefreshToken     EncryptedToken
	CreatedAt           time.Time
	LastUsedAt          time.Time
	// ExpiresAt is the absolute end of the session.
	ExpiresAt time.Time
}
