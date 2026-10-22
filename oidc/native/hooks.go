package native

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/oidc"
	"github.com/foomo/gosso/oidc/native/repository/store"
)

// Login-context keys the broker puts on a native login.
const (
	lcNative        = "gosso.native"
	lcClientID      = "gosso.native.client_id"
	lcRedirectURI   = "gosso.native.redirect_uri"
	lcState         = "gosso.native.state"
	lcCodeChallenge = "gosso.native.code_challenge"
)

// passthroughIDPErrors are IdP authorize errors the app sees as-is; any
// other failure becomes server_error.
var passthroughIDPErrors = []string{
	"access_denied",
	"login_required",
	"interaction_required",
	"consent_required",
	"temporarily_unavailable",
}

// nativeLogin is the native part of a login context.
type nativeLogin struct {
	clientID    string
	redirectURI string
	state       string
	challenge   string
}

func nativeLoginFrom(lc oidc.LoginContext) (nativeLogin, bool) {
	if lc[lcNative] != "1" {
		return nativeLogin{}, false
	}

	return nativeLogin{
		clientID:    lc[lcClientID],
		redirectURI: lc[lcRedirectURI],
		state:       lc[lcState],
		challenge:   lc[lcCodeChallenge],
	}, true
}

func nativeLoginFromContext(ctx context.Context) (nativeLogin, bool) {
	lc, ok := oidc.LoginContextFromContext(ctx)
	if !ok {
		return nativeLogin{}, false
	}

	return nativeLoginFrom(lc)
}

func (n nativeLogin) loginContext() oidc.LoginContext {
	return oidc.LoginContext{
		lcNative:        "1",
		lcClientID:      n.clientID,
		lcRedirectURI:   n.redirectURI,
		lcState:         n.state,
		lcCodeChallenge: n.challenge,
	}
}

// OnAuthenticated wraps the web OnAuthenticated hook. Native logins skip
// it, so they set no web session; all others are delegated to web, or fail
// when web is nil.
func (b *Broker) OnAuthenticated(web sso.OnAuthenticated[oidc.Payload]) sso.OnAuthenticated[oidc.Payload] {
	b.wrapMu.Lock()
	b.wrappedAuth = true
	b.wrapMu.Unlock()

	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, sub sso.Subject[oidc.Payload]) error {
		if _, ok := nativeLoginFromContext(ctx); ok {
			return nil
		}

		if web == nil {
			return errors.New("native: web login not configured")
		}

		return web(ctx, w, r, sub)
	}
}

// OnRedirect wraps the web OnRedirect hook. For a native login it runs
// Hooks.Authenticate, stores a one-time code and redirects to the app's
// redirect URI with code and state; an error there reaches OnLoginError,
// which redirects the app with error=server_error. Other logins are
// delegated to web (nil keeps the default target).
func (b *Broker) OnRedirect(web oidc.OnRedirect) oidc.OnRedirect {
	b.wrapMu.Lock()
	b.wrappedRedirect = true
	b.wrapMu.Unlock()

	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, sub sso.Subject[oidc.Payload], target string) (string, error) {
		n, ok := nativeLoginFromContext(ctx)
		if !ok {
			if web == nil {
				return "", nil
			}

			return web(ctx, w, r, sub, target)
		}

		return b.issueCode(ctx, r, n, sub)
	}
}

// checkRegistered verifies that a native login's client and redirect URI
// are still registered: the login context is signed, but the
// configuration may have changed since the login started.
func (b *Broker) checkRegistered(n nativeLogin) error {
	if _, known, allowed := b.client(n.clientID, n.redirectURI); !known || !allowed {
		return fmt.Errorf("native: client %q or redirect uri no longer registered", n.clientID)
	}

	return nil
}

func (b *Broker) issueCode(ctx context.Context, r *http.Request, n nativeLogin, sub sso.Subject[oidc.Payload]) (string, error) {
	if err := b.checkRegistered(n); err != nil {
		return "", err
	}

	if sub.Raw.RefreshToken == "" {
		return "", errors.New("native: IdP issued no refresh token (offline_access?)")
	}

	attrs, err := b.hooks.Authenticate(ctx, r, sub)
	if err != nil {
		return "", fmt.Errorf("native: authenticate: %w", err)
	}

	sealed, err := b.sealer.seal(sub.Raw.RefreshToken, sealAAD(sub.ExternalID))
	if err != nil {
		return "", fmt.Errorf("native: seal idp refresh token: %w", err)
	}

	code, err := randomToken(32)
	if err != nil {
		return "", err
	}

	if err := b.codes.Put(ctx, store.Code{
		Hash:            hashToken(code),
		ClientID:        n.clientID,
		RedirectURI:     n.redirectURI,
		CodeChallenge:   n.challenge,
		Subject:         projectSubject(sub),
		Attributes:      cloneAttributes(attrs),
		IDPRefreshToken: sealed,
		ExpiresAt:       b.now().Add(b.codeTTL),
	}); err != nil {
		return "", fmt.Errorf("native: store code: %w", err)
	}

	return nativeRedirectURL(n.redirectURI, url.Values{"code": {code}, "state": {n.state}})
}

// OnLoginError wraps the web OnLoginError hook. A failed native login
// redirects to the app with error and state: the IdP's own error for a
// user-facing outcome (access_denied, login_required, ...), server_error
// for everything else. Other logins are delegated to web (nil keeps the
// default error response).
func (b *Broker) OnLoginError(web oidc.OnLoginError) oidc.OnLoginError {
	b.wrapMu.Lock()
	b.wrappedLoginError = true
	b.wrapMu.Unlock()

	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, lc oidc.LoginContext, stage string, err error) string {
		n, ok := nativeLoginFrom(lc)
		if !ok {
			if web == nil {
				return ""
			}

			return web(ctx, w, r, lc, stage, err)
		}

		b.logError(r, "native-login-"+stage, err)

		if err := b.checkRegistered(n); err != nil {
			b.logError(r, "native-login-redirect", err)
			return ""
		}

		code := errServerError
		if idpErr := r.URL.Query().Get("error"); stage == oidc.StageIDPError && slices.Contains(passthroughIDPErrors, idpErr) {
			code = idpErr
		}

		redirect, rerr := nativeRedirectURL(n.redirectURI, url.Values{"error": {code}, "state": {n.state}})
		if rerr != nil {
			b.logError(r, "native-login-redirect", rerr)
			return ""
		}

		return redirect
	}
}
