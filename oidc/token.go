package oidc

import "time"

// oauthToken is a protocol-agnostic projection of oauth2.Token so
// buildSubject can be exercised from tests without constructing a full
// *oauth2.Token.
type oauthToken struct {
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}
