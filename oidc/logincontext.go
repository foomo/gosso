package oidc

import (
	"context"
	"maps"
	"net/http"

	"github.com/foomo/gosso/internal/safepath"
)

// LoginContext is consumer-defined data carried, signed but not encrypted,
// in the transit cookie from login start to the callback hooks. Never put
// secrets in it: the browser can read it.
type LoginContext map[string]string

// LoginOption configures a single login started with RP.Login.
type LoginOption func(*loginOptions)

type loginOptions struct {
	target  string
	context LoginContext
	onError func(w http.ResponseWriter, r *http.Request, err error)
}

// WithLoginTarget sets the post-login target. Like ?target= on the login
// handler, it is sanitised: only app-local paths are kept, anything else
// becomes "/".
func WithLoginTarget(target string) LoginOption {
	return func(o *loginOptions) {
		o.target = target
	}
}

// WithLoginContext attaches lc to the login. OnAuthenticated, OnRedirect
// and OnLoginError see it again on the callback. The map is cloned; nil
// or empty means no context.
func WithLoginContext(lc LoginContext) LoginOption {
	return func(o *loginOptions) {
		if len(lc) == 0 {
			o.context = nil
			return
		}

		o.context = maps.Clone(lc)
	}
}

// WithLoginInitError replaces the default 500 response when the login
// cannot start (random generation failed, transit cookie too large). fn
// owns the response; nothing has been written yet.
func WithLoginInitError(fn func(w http.ResponseWriter, r *http.Request, err error)) LoginOption {
	return func(o *loginOptions) {
		o.onError = fn
	}
}

type loginContextKey struct{}

func withLoginContext(ctx context.Context, lc LoginContext) context.Context {
	return context.WithValue(ctx, loginContextKey{}, lc)
}

// LoginContextFromContext returns the login context of the login being
// completed. It is set inside OnAuthenticated and OnRedirect when the
// login was started with WithLoginContext. The result is a copy.
func LoginContextFromContext(ctx context.Context) (LoginContext, bool) {
	lc, ok := ctx.Value(loginContextKey{}).(LoginContext)
	if !ok {
		return nil, false
	}

	return maps.Clone(lc), true
}

// Login starts an authorization request: it generates fresh state, nonce
// and PKCE values, stores them with the target and login context in the
// signed transit cookie and redirects to the IdP. Handlers().Login is
// Login with the target taken from ?target=.
func (rp *RP) Login(w http.ResponseWriter, r *http.Request, opts ...LoginOption) {
	ctx := r.Context()

	var o loginOptions
	for _, opt := range opts {
		opt(&o)
	}

	initFailed := func(stage string, err error) {
		rp.fail(ctx, r, nil, stage, err)

		if o.onError != nil {
			o.onError(w, r, err)
			return
		}

		http.Error(w, "login init failed", http.StatusInternalServerError)
	}

	state, err := generateState()
	if err != nil {
		initFailed("generate-state", err)
		return
	}

	nonce, err := generateNonce()
	if err != nil {
		initFailed("generate-nonce", err)
		return
	}

	verifier, err := generateVerifier()
	if err != nil {
		initFailed("generate-verifier", err)
		return
	}

	if err := rp.transit.write(w, transitData{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		Target:       safepath.Target(o.target),
		Context:      o.context,
	}); err != nil {
		initFailed("transit-write", err)
		return
	}

	http.Redirect(w, r, rp.authorizeURL(state, nonce, codeChallenge(verifier)), http.StatusFound)
}
