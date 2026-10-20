package store

import (
	"time"
)

// Code is a pending one-time authorization code. Hash is the code's
// base64url(SHA-256); the code itself is never stored.
type Code struct {
	Hash            string
	ClientID        string
	RedirectURI     string
	CodeChallenge   string
	Subject         Subject
	Attributes      Attributes
	IDPRefreshToken EncryptedToken
	ExpiresAt       time.Time
}
