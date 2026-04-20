package oidc

import (
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
)

// Payload is the OIDC-specific data carried in sso.Subject[Payload].Raw.
type Payload struct {
	// IDToken is the verified ID token. Treat as read-only: further
	// calls to Claims() decode into the caller's destination and are
	// otherwise side-effect free.
	IDToken *gooidc.IDToken
	// RawIDToken is the serialised JWT — useful as an id_token_hint on
	// RP-initiated logout, for forwarding, or for logging.
	RawIDToken string
	// AccessToken is the OAuth2 access token returned by the token
	// endpoint. It may be empty if the IdP only issued an ID token.
	AccessToken string
	// TokenExpiry is the access token's expiry.
	TokenExpiry time.Time
	// RefreshToken is the OAuth2 refresh token, present only when the
	// `offline_access` scope was granted.
	RefreshToken string
	// UserInfo holds the raw claims from the UserInfo endpoint, set only
	// if WithUserInfo(true) was supplied and the call succeeded.
	UserInfo map[string]any
}
