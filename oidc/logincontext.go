package oidc

import (
	"context"
	"maps"
	"net/http"

	"github.com/foomo/go/options"
	"go.opentelemetry.io/otel/trace"

	"github.com/foomo/gosso/internal/safepath"
	"github.com/foomo/gosso/internal/telemetry"
	"github.com/foomo/gosso/internal/tokens"
)

// LoginContext is consumer-defined data carried, signed but not encrypted,
// in the transit cookie from login start to the callback hooks. Never put
// secrets in it: the browser can read it.
type LoginContext map[string]string

// LoginOption configures a single login started with RP.Login.
type LoginOption = options.Option[*loginOptions]

type loginOptions struct {
	target  string
	context LoginContext
	scopes  []string
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

// WithLoginScopes requests scopes for this login on top of the RP's own
// (WithScopes, WithExtraScopes). Use it for a scope only some logins
// need, such as offline_access for the native broker: requested on every
// login, it would open an offline session at the IdP for each web login
// too.
func WithLoginScopes(scopes ...string) LoginOption {
	return func(o *loginOptions) {
		o.scopes = append(o.scopes, scopes...)
	}
}

// WithLoginInitError replaces the default 500 response when the login
// cannot start (transit cookie too large). fn owns the response; nothing
// has been written yet.
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
// Login with the target taken from ?target=. Every login started here
// counts in the login telemetry, the native broker's included.
func (rp *RP) Login(w http.ResponseWriter, r *http.Request, opts ...LoginOption) {
	ctx, span := telemetry.Tracer().Start(r.Context(), "oidc.login",
		trace.WithAttributes(oidcProtocolAttr),
	)
	defer span.End()

	r = r.WithContext(ctx)

	loginStarted.Add(ctx, 1)

	var o loginOptions
	options.Apply(&o, opts...)

	initFailed := func(stage string, err error) {
		rp.fail(ctx, r, nil, stage, err)

		if o.onError != nil {
			o.onError(w, r, err)
			return
		}

		http.Error(w, "login init failed", http.StatusInternalServerError)
	}

	// 32 random bytes each; the verifier is 43 characters, within RFC
	// 7636 §4.1's 43–128
	state := tokens.Random(32)
	nonce := tokens.Random(32)
	verifier := tokens.Random(32)

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

	http.Redirect(w, r, rp.authorizeURL(state, nonce, tokens.S256(verifier), o.scopes), http.StatusFound)
}
