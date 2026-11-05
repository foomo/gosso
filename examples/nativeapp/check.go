package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// rfc7636Challenge is S256 of the RFC 7636 appendix B verifier.
const rfc7636Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

// response is a read HTTP response that was not redirected.
type response struct {
	status   int
	header   http.Header
	location *url.URL
	body     string
	oauthErr string
}

// scenarioCheck runs the broker's protocol checks that need no login:
// authorize validation, token and revoke error shapes, and the bearer
// check on /app/whoami.
func scenarioCheck(ctx context.Context, c *client) error {
	authorize := func(mutate func(url.Values)) url.Values {
		q := url.Values{
			"client_id":             {c.clientID},
			"redirect_uri":          {c.redirect},
			"response_type":         {"code"},
			"state":                 {"s1"},
			"code_challenge":        {rfc7636Challenge},
			"code_challenge_method": {"S256"},
		}
		mutate(q)

		return q
	}

	token := func(form url.Values) url.Values {
		if !form.Has("client_id") {
			form.Set("client_id", c.clientID)
		}

		return form
	}

	checks := []struct {
		name string
		run  func() (response, error)
		want func(response) error
	}{
		{
			"authorize: valid request starts the IdP login",
			func() (response, error) { return c.get(ctx, "/oidc/app/authorize", authorize(func(url.Values) {})) },
			func(r response) error {
				if r.status != http.StatusFound || r.location == nil || !strings.Contains(r.location.Path, "/realms/") {
					return fmt.Errorf("want 302 to Keycloak, got %d %v", r.status, r.location)
				}

				if !strings.Contains(r.header.Get("Set-Cookie"), "gosso_oidc_transit=") {
					return errors.New("no transit cookie set")
				}

				return nil
			},
		},
		{
			"authorize: unknown client_id → 400, no redirect",
			func() (response, error) {
				return c.get(ctx, "/oidc/app/authorize", authorize(func(q url.Values) { q.Set("client_id", "nope") }))
			},
			wantPlain(http.StatusBadRequest),
		},
		{
			"authorize: unregistered redirect_uri → 400, no redirect",
			func() (response, error) {
				return c.get(ctx, "/oidc/app/authorize", authorize(func(q url.Values) { q.Set("redirect_uri", "http://127.0.0.1:9999/x") }))
			},
			wantPlain(http.StatusBadRequest),
		},
		{
			"authorize: PKCE plain → redirect error=invalid_request",
			func() (response, error) {
				return c.get(ctx, "/oidc/app/authorize", authorize(func(q url.Values) { q.Set("code_challenge_method", "plain") }))
			},
			wantAppError(c.redirect, "invalid_request", "s1"),
		},
		{
			"authorize: malformed code_challenge → redirect error=invalid_request",
			func() (response, error) {
				return c.get(ctx, "/oidc/app/authorize", authorize(func(q url.Values) { q.Set("code_challenge", "short") }))
			},
			wantAppError(c.redirect, "invalid_request", "s1"),
		},
		{
			"authorize: hostile state → redirect error=invalid_request",
			func() (response, error) {
				return c.get(ctx, "/oidc/app/authorize", authorize(func(q url.Values) { q.Set("state", strings.Repeat("<", 64)) }))
			},
			wantAppError(c.redirect, "invalid_request", ""),
		},
		{
			"authorize: response_type=token → redirect error=unsupported_response_type",
			func() (response, error) {
				return c.get(ctx, "/oidc/app/authorize", authorize(func(q url.Values) { q.Set("response_type", "token") }))
			},
			wantAppError(c.redirect, "unsupported_response_type", "s1"),
		},
		{
			"token: grant_type=password → 400 unsupported_grant_type",
			func() (response, error) {
				return c.post(ctx, "/oidc/app/token", token(url.Values{"grant_type": {"password"}}))
			},
			wantOAuth(http.StatusBadRequest, "unsupported_grant_type"),
		},
		{
			"token: unknown client_id → 400 invalid_client",
			func() (response, error) {
				return c.post(ctx, "/oidc/app/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"a.b"}, "client_id": {"nope"}})
			},
			wantOAuth(http.StatusBadRequest, "invalid_client"),
		},
		{
			"token: unknown code → 400 invalid_grant",
			func() (response, error) {
				return c.post(ctx, "/oidc/app/token", token(url.Values{
					"grant_type": {"authorization_code"}, "code": {"nope"}, "redirect_uri": {c.redirect},
					"code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
				}))
			},
			wantOAuth(http.StatusBadRequest, "invalid_grant"),
		},
		{
			"token: code_verifier too short → 400 invalid_request",
			func() (response, error) {
				return c.post(ctx, "/oidc/app/token", token(url.Values{
					"grant_type": {"authorization_code"}, "code": {"nope"}, "redirect_uri": {c.redirect},
					"code_verifier": {"too-short"},
				}))
			},
			wantOAuth(http.StatusBadRequest, "invalid_request"),
		},
		{
			"token: malformed refresh token → 400 invalid_grant",
			func() (response, error) {
				return c.post(ctx, "/oidc/app/token", token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"garbage"}}))
			},
			wantOAuth(http.StatusBadRequest, "invalid_grant"),
		},
		{
			"revoke: unknown token → 200 {}",
			func() (response, error) {
				return c.post(ctx, "/oidc/app/revoke", token(url.Values{"token": {"garbage"}}))
			},
			func(r response) error {
				if r.status != http.StatusOK || strings.TrimSpace(r.body) != "{}" {
					return fmt.Errorf("want 200 {}, got %d %s", r.status, r.body)
				}

				return wantNoStore(r)
			},
		},
		{
			"revoke: missing token → 400 invalid_request",
			func() (response, error) { return c.post(ctx, "/oidc/app/revoke", token(url.Values{})) },
			wantOAuth(http.StatusBadRequest, "invalid_request"),
		},
		{
			"whoami: no bearer token → 401 invalid_token",
			func() (response, error) { return c.get(ctx, "/app/whoami", nil) },
			func(r response) error {
				if r.status != http.StatusUnauthorized || !strings.Contains(r.header.Get("WWW-Authenticate"), `error="invalid_token"`) {
					return fmt.Errorf("want 401 with WWW-Authenticate invalid_token, got %d %q", r.status, r.header.Get("WWW-Authenticate"))
				}

				return nil
			},
		},
	}

	var failed []string

	for _, ch := range checks {
		r, err := ch.run()
		if err == nil {
			err = ch.want(r)
		}

		if err != nil {
			fmt.Printf("   ✗ %s: %v\n", ch.name, err)
			failed = append(failed, ch.name)

			continue
		}

		fmt.Printf("   ✓ %s\n", ch.name)
	}

	if len(failed) > 0 {
		return fmt.Errorf("%d of %d checks failed", len(failed), len(checks))
	}

	c.logf("all %d protocol checks passed", len(checks))

	return nil
}

func wantPlain(status int) func(response) error {
	return func(r response) error {
		if r.status != status || r.location != nil {
			return fmt.Errorf("want %d without redirect, got %d %v", status, r.status, r.location)
		}

		return nil
	}
}

func wantAppError(redirect, code, state string) func(response) error {
	return func(r response) error {
		if r.status != http.StatusFound || r.location == nil {
			return fmt.Errorf("want 302 to the app, got %d", r.status)
		}

		if !strings.HasPrefix(r.location.String(), redirect+"?") {
			return fmt.Errorf("redirect went to %s, not the app", r.location)
		}

		q := r.location.Query()
		if q.Get("error") != code {
			return fmt.Errorf("want error=%s, got %q", code, q.Get("error"))
		}

		if q.Get("state") != state {
			return fmt.Errorf("want state=%q, got %q", state, q.Get("state"))
		}

		return nil
	}
}

func wantOAuth(status int, code string) func(response) error {
	return func(r response) error {
		if r.status != status || r.oauthErr != code {
			return fmt.Errorf("want %d %s, got %d %s", status, code, r.status, r.body)
		}

		return wantNoStore(r)
	}
}

func wantNoStore(r response) error {
	if r.header.Get("Cache-Control") != "no-store" || r.header.Get("Pragma") != "no-cache" {
		return fmt.Errorf("missing no-store headers: Cache-Control=%q Pragma=%q", r.header.Get("Cache-Control"), r.header.Get("Pragma"))
	}

	return nil
}

// noRedirect is an HTTP client that reports redirects instead of following
// them.
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}}

func (c *client) get(ctx context.Context, path string, q url.Values) (response, error) {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return response{}, err
	}

	return do(req)
}

func (c *client) post(ctx context.Context, path string, form url.Values) (response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, strings.NewReader(form.Encode()))
	if err != nil {
		return response{}, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return do(req)
}

func do(req *http.Request) (response, error) {
	resp, err := noRedirect.Do(req)
	if err != nil {
		return response{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return response{}, err
	}

	r := response{status: resp.StatusCode, header: resp.Header, body: string(body)}

	if loc := resp.Header.Get("Location"); loc != "" {
		if r.location, err = url.Parse(loc); err != nil {
			return response{}, err
		}
	}

	var oe struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &oe) == nil {
		r.oauthErr = oe.Error
	}

	return r, nil
}
