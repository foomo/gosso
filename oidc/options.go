package oidc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/foomo/go/options"

	sso "github.com/foomo/gosso"
)

// minTransitSigningKeyBytes is the minimum accepted length for the HMAC
// signing key protecting the transit cookie. One HMAC-SHA256 block.
const minTransitSigningKeyBytes = 32

// Option configures an RP.
type Option = options.OptionE[*RP]

// WithExtraScopes appends scopes to the default {openid, profile, email}
// set. Most commonly used to request `offline_access` for refresh
// tokens.
func WithExtraScopes(scopes ...string) Option {
	return func(rp *RP) error {
		rp.extraScopes = append(rp.extraScopes, scopes...)
		return nil
	}
}

// WithClaimMap overrides the default claim names used to populate
// sso.Subject.
func WithClaimMap(m ClaimMap) Option {
	return func(rp *RP) error {
		rp.claimMap = m
		return nil
	}
}

// WithUserInfo enables a call to the UserInfo endpoint after the token
// exchange. Claims from UserInfo are merged into the result and override
// claims from the ID token on conflict. The UserInfo `sub` is verified
// to equal the ID token `sub` per OIDC Core §5.3.2 before merging.
func WithUserInfo(enabled bool) Option {
	return func(rp *RP) error {
		rp.fetchUserInfo = enabled
		return nil
	}
}

// WithIssuerValidator overrides the default strict issuer check. Use
// this to accept e.g. Microsoft Entra ID's tenant-GUID issuer pattern.
// Passing nil restores the default (strict equality with the issuer
// URL).
//
// WARNING: when a validator is configured, the underlying go-oidc
// verifier's issuer check is disabled and the validator is the only
// gate. A buggy validator that returns nil unconditionally silently
// accepts any issuer — write the validator with care. Example:
//
//	oidc.WithIssuerValidator(func(iss string) error {
//	    if strings.HasPrefix(iss, "https://login.microsoftonline.com/") &&
//	        strings.HasSuffix(iss, "/v2.0") {
//	        return nil
//	    }
//	    return fmt.Errorf("unexpected issuer: %s", iss)
//	})
func WithIssuerValidator(fn func(iss string) error) Option {
	return func(rp *RP) error {
		rp.issuerValidator = fn
		return nil
	}
}

// WithTransitDeprecatedKeys adds previously-used signing keys that are
// still accepted when verifying incoming transit cookies. Supports key
// rotation. Each key must meet the same minimum length as the primary.
func WithTransitDeprecatedKeys(keys ...[]byte) Option {
	return func(rp *RP) error {
		for _, k := range keys {
			if len(k) == 0 {
				continue
			}

			if len(k) < minTransitSigningKeyBytes {
				return fmt.Errorf("deprecated transit signing key must be at least %d bytes, got %d", minTransitSigningKeyBytes, len(k))
			}

			rp.transitDeprecatedKeys = append(rp.transitDeprecatedKeys, append([]byte(nil), k...))
		}

		return nil
	}
}

// WithTransitCookieName overrides the default transit cookie name.
func WithTransitCookieName(name string) Option {
	return func(rp *RP) error {
		if name == "" {
			return fmt.Errorf("transit cookie name must not be empty")
		}

		rp.transitCookieName = name

		return nil
	}
}

// WithTransitTTL overrides the default transit cookie lifetime (5 min).
func WithTransitTTL(d time.Duration) Option {
	return func(rp *RP) error {
		if d <= 0 {
			return fmt.Errorf("transit ttl must be > 0")
		}

		rp.transitTTL = d

		return nil
	}
}

// WithOnLogout registers a callback invoked before the RP-initiated
// logout redirect (if any).
func WithOnLogout(fn sso.OnLogout) Option {
	return func(rp *RP) error {
		rp.onLogout = fn
		return nil
	}
}

// WithErrorLogger routes runtime errors encountered by the OIDC
// handlers to the supplied logger. HTTP responses stay generic
// regardless; the logger sees the underlying cause.
func WithErrorLogger(fn sso.ErrorLogger) Option {
	return func(rp *RP) error {
		rp.errorLogger = fn
		return nil
	}
}

// LogoutHintProvider returns the raw ID token (typically extracted from
// the consumer's session) to be included as id_token_hint in an
// RP-initiated logout request. Returning an empty string skips the
// IdP-side SLO.
type LogoutHintProvider func(*http.Request) string

// WithLogoutHintProvider configures the callback used by the logout
// handler to populate `id_token_hint` on the end-session URL.
func WithLogoutHintProvider(fn LogoutHintProvider) Option {
	return func(rp *RP) error {
		rp.logoutHintProvider = fn
		return nil
	}
}

// OnRedirect computes the post-login redirect destination. It runs after a
// successful OnAuthenticated, receiving the authenticated subject and the
// resolved (safe) target from the transit state. Returning a non-empty string
// overrides the redirect destination; returning "" keeps the default target.
// Returning an error aborts the callback. It owns the ResponseWriter, so a
// consumer may set additional cookies (e.g. rebinding a cart on login) before
// the redirect happens.
//
// Keeping the redirect decision here — rather than inside OnAuthenticated —
// lets the consumer branch on where login was initiated (the target), which
// OnAuthenticated does not see.
type OnRedirect func(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	sub sso.Subject[Payload],
	target string,
) (finalTarget string, err error)

// WithOnRedirect registers a callback that computes the final post-login
// redirect target. See OnRedirect. When unset, the callback redirects to the
// transit target (or "/") unchanged.
func WithOnRedirect(fn OnRedirect) Option {
	return func(rp *RP) error {
		rp.onRedirect = fn
		return nil
	}
}

// WithPostLogoutRedirectURL sets the URL the IdP will redirect back to
// after a successful RP-initiated logout.
func WithPostLogoutRedirectURL(u string) Option {
	return func(rp *RP) error {
		rp.postLogoutRedirectURL = u
		return nil
	}
}

// WithHTTPClient overrides the client used for discovery, token and
// UserInfo calls. The default client has a 15 second Timeout; a client
// supplied here is used as-is — set your own Timeout if you want one.
func WithHTTPClient(c *http.Client) Option {
	return func(rp *RP) error {
		if c == nil {
			return fmt.Errorf("http client must not be nil")
		}

		rp.httpClient = c

		return nil
	}
}

// WithBootstrapTimeout bounds the time `New` will spend on OIDC
// discovery. Defaults to 30s. Values ≤ 0 are rejected.
func WithBootstrapTimeout(d time.Duration) Option {
	return func(rp *RP) error {
		if d <= 0 {
			return fmt.Errorf("bootstrap timeout must be > 0")
		}

		rp.bootstrapTimeout = d

		return nil
	}
}

// requireSecureURL rejects non-HTTPS URLs unless the host is a loopback
// address, which is allowed over plain HTTP for local development.
func requireSecureURL(u *url.URL, label string) error {
	if u.Scheme == "https" {
		return nil
	}

	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return nil
	}

	return fmt.Errorf("%s must be https (loopback exception): %s", label, u.String())
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}
