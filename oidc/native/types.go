package native

import (
	"context"
	"net/http"
	"time"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/oidc"
)

// Client is a registered native app: a public client without a secret.
type Client struct {
	// ID is the client_id the app sends, e.g. "app-ios".
	ID string
	// RedirectURIs are the app's redirect URIs, matched exactly.
	RedirectURIs []string
}

// Attributes are opaque consumer data returned by Hooks.Authenticate and
// stored on codes and sessions.
type Attributes map[string]string

// Subject is the storable projection of sso.Subject kept on codes and
// sessions.
type Subject struct {
	ExternalID string
	Email      string
	Firstname  string
	Lastname   string
	Groups     []string
}

// Tokens are the consumer's tokens for a session, minted by Hooks.Mint.
type Tokens struct {
	// AccessToken is returned as access_token with token_type "Bearer".
	AccessToken string
	// ExpiresIn is returned as expires_in, in whole seconds.
	ExpiresIn time.Duration
}

// Hooks are the consumer's part of the broker.
type Hooks struct {
	// Authenticate runs after a native login and after each successful
	// refresh. It returns attributes stored on the session. An error fails
	// the login (redirect with error=server_error) or the refresh (503,
	// session kept).
	Authenticate func(ctx context.Context, r *http.Request, sub sso.Subject[oidc.Payload]) (Attributes, error)
	// Mint issues the consumer's access token for a session. It decides
	// the token format.
	Mint func(ctx context.Context, s Session) (Tokens, error)
}

// EncryptedToken is an AES-256-GCM ciphertext (nonce prefixed) and the ID
// of the key that sealed it.
type EncryptedToken struct {
	KeyID      string
	Ciphertext []byte
}

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

func projectSubject(sub sso.Subject[oidc.Payload]) Subject {
	return Subject{
		ExternalID: sub.ExternalID,
		Email:      sub.Email,
		Firstname:  sub.Firstname,
		Lastname:   sub.Lastname,
		Groups:     cloneGroups(sub.Groups),
	}
}
