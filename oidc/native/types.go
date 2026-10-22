package native

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"time"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/oidc"
	"github.com/foomo/gosso/oidc/native/repository/store"
)

// Client is a registered native app: a public client without a secret.
type Client struct {
	// ID is the client_id the app sends, e.g. "app-ios".
	ID string
	// RedirectURIs are the app's redirect URIs, matched exactly.
	RedirectURIs []string
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
	Authenticate func(ctx context.Context, r *http.Request, sub sso.Subject[oidc.Payload]) (store.Attributes, error)
	// Mint issues the consumer's access token for a session. It decides
	// the token format.
	Mint func(ctx context.Context, s store.Session) (Tokens, error)
}

func projectSubject(sub sso.Subject[oidc.Payload]) store.Subject {
	return store.Subject{
		ExternalID: sub.ExternalID,
		Email:      sub.Email,
		Firstname:  sub.Firstname,
		Lastname:   sub.Lastname,
		Groups:     cloneGroups(sub.Groups),
	}
}

// cloneGroups copies groups; nil and empty both become nil.
func cloneGroups(g []string) []string {
	if len(g) == 0 {
		return nil
	}

	return slices.Clone(g)
}

func cloneAttributes(a store.Attributes) store.Attributes {
	if a == nil {
		return nil
	}

	return maps.Clone(a)
}
