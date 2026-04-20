package oidc

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	"github.com/foomo/gosso/internal/telemetry"
)

// handleCallback completes the Authorization Code flow: it validates
// state, exchanges the authorization code, verifies the ID token
// (signature, audience, expiry, nonce, issuer) and then invokes
// OnAuthenticated.
func (rp *RP) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx, span := telemetry.Tracer().Start(r.Context(), "oidc.callback",
		trace.WithAttributes(oidcProtocolAttr),
	)
	defer span.End()

	ctx = gooidc.ClientContext(ctx, rp.httpClient)
	r = r.WithContext(ctx)

	start := time.Now()

	callbackStarted.Add(ctx, 1)

	defer func() {
		callbackDuration.Record(ctx, time.Since(start).Milliseconds())
	}()

	fail := func(stage string, err error, status int, msg string) {
		rp.fail(ctx, r, callbackCompleted, stage, err)
		http.Error(w, msg, status)
	}

	td, err := rp.transit.read(r)
	// Always clear the transit cookie after a read attempt: a valid
	// cookie must not replay, and a stale/invalid cookie shouldn't keep
	// being resubmitted on every callback retry.
	rp.transit.delete(w)

	if err != nil {
		fail("transit-read", err, http.StatusBadRequest, "invalid callback state")
		return
	}

	got := r.URL.Query().Get("state")
	if subtle.ConstantTimeCompare([]byte(got), []byte(td.State)) != 1 {
		fail("state-mismatch", fmt.Errorf("state mismatch"), http.StatusBadRequest, "state mismatch")
		return
	}

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		fail("idp-error", fmt.Errorf("idp error: %s", errParam), http.StatusBadGateway, "idp error")
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		fail("missing-code", fmt.Errorf("missing authorization code"), http.StatusBadRequest, "missing authorization code")
		return
	}

	tokStart := time.Now()
	tok, err := rp.oauth2Cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", td.CodeVerifier),
	)
	tokenExchangeDuration.Record(ctx, time.Since(tokStart).Milliseconds())

	if err != nil {
		fail("token-exchange", err, http.StatusBadGateway, "token exchange failed")
		return
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		fail("missing-id-token", fmt.Errorf("missing id_token in token response"), http.StatusBadGateway, "missing id token")
		return
	}

	idToken, err := rp.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		fail("verify-id-token", err, http.StatusUnauthorized, "id token verification failed")
		return
	}

	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(td.Nonce)) != 1 {
		fail("nonce-mismatch", fmt.Errorf("nonce mismatch"), http.StatusUnauthorized, "nonce mismatch")
		return
	}

	if rp.issuerValidator != nil {
		if err := rp.issuerValidator(idToken.Issuer); err != nil {
			fail("issuer-validation", err, http.StatusUnauthorized, "issuer validation failed")
			return
		}
	}

	var userInfo map[string]any

	if rp.fetchUserInfo {
		uiStart := time.Now()
		ui, uiErr := rp.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		userinfoDuration.Record(ctx, time.Since(uiStart).Milliseconds())

		if uiErr != nil {
			fail("userinfo", uiErr, http.StatusBadGateway, "userinfo failed")
			return
		}

		// OIDC Core §5.3.2: UserInfo `sub` MUST equal ID token `sub`.
		// Reject mismatches rather than let a bad UserInfo override the
		// principal's identity.
		if ui.Subject != idToken.Subject {
			fail("userinfo-sub-mismatch", fmt.Errorf("userinfo sub != id token sub"), http.StatusUnauthorized, "userinfo sub mismatch")
			return
		}

		userInfo = map[string]any{}
		if err := ui.Claims(&userInfo); err != nil {
			fail("userinfo-claims", err, http.StatusBadGateway, "userinfo claims parse failed")
			return
		}
	}

	sub, err := buildSubject(idToken, rawIDToken, oauthToken{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Expiry:       tok.Expiry,
	}, userInfo, rp.claimMap)
	if err != nil {
		fail("build-subject", err, http.StatusInternalServerError, "build subject failed")
		return
	}

	if err := rp.onAuthenticated(ctx, w, r, sub); err != nil {
		fail("on-authenticated", err, http.StatusInternalServerError, "authentication callback failed")
		return
	}

	callbackCompleted.Add(ctx, 1, metric.WithAttributes(
		attribute.String(telemetry.AttrOutcome, "success"),
	))

	target := td.Target
	if target == "" {
		target = "/"
	}

	http.Redirect(w, r, target, http.StatusFound)
}
