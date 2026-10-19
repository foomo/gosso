package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/internal/telemetry"
)

// ErrRefreshRejected means the IdP answered the refresh grant with
// invalid_grant: the refresh token is expired, revoked or unknown, and the
// session it backs is over.
var ErrRefreshRejected = errors.New("oidc: refresh token rejected")

// RefreshFailedError is returned by Refresh when the IdP granted the
// refresh but a later step failed (ID-token verification, UserInfo, subject
// check, ...). The IdP may already have retired the input token, so store
// RefreshToken (the token it issued, or the input when it did not rotate)
// before retrying. It is never ErrRefreshRejected.
type RefreshFailedError struct {
	RefreshToken string
	Err          error
}

func (e *RefreshFailedError) Error() string { return e.Err.Error() }

func (e *RefreshFailedError) Unwrap() error { return e.Err }

// Refresh redeems an IdP refresh token. The returned subject is rebuilt from
// the refreshed ID token, or from UserInfo when the IdP returns none; its
// ExternalID must equal expectedExternalID. Payload.RefreshToken holds the
// token to store next (rotated, or the input when the IdP did not rotate).
// ErrRefreshRejected means the IdP answered invalid_grant (session over);
// any other error is transient. A failure after the grant succeeded is a
// *RefreshFailedError carrying the refresh token to keep.
//
// Refresh does not call the ErrorLogger: there is no request to log
// against, so the caller logs.
func (rp *RP) Refresh(ctx context.Context, refreshToken, expectedExternalID string) (sso.Subject[Payload], error) {
	ctx, span := telemetry.Tracer().Start(ctx, "oidc.refresh",
		trace.WithAttributes(oidcProtocolAttr),
	)
	defer span.End()

	start := time.Now()

	defer func() {
		refreshDuration.Record(ctx, time.Since(start).Milliseconds())
	}()

	sub, stage, err := rp.refresh(ctx, refreshToken, expectedExternalID)
	if err != nil {
		outcome := "failure"
		if errors.Is(err, ErrRefreshRejected) {
			outcome = "rejected"
		}

		span.RecordError(err, trace.WithAttributes(attribute.String(telemetry.AttrStage, stage)))
		span.SetStatus(codes.Error, stage)
		refreshCompleted.Add(ctx, 1, metric.WithAttributes(
			attribute.String(telemetry.AttrOutcome, outcome),
			attribute.String(telemetry.AttrStage, stage),
		))

		return sso.Subject[Payload]{}, err
	}

	refreshCompleted.Add(ctx, 1, metric.WithAttributes(
		attribute.String(telemetry.AttrOutcome, "success"),
	))

	return sub, nil
}

// refresh does the work of Refresh and names the failing stage.
func (rp *RP) refresh(ctx context.Context, refreshToken, expectedExternalID string) (sso.Subject[Payload], string, error) {
	if refreshToken == "" {
		return sso.Subject[Payload]{}, "missing-refresh-token", fmt.Errorf("%w: empty refresh token", ErrRefreshRejected)
	}

	ctx = gooidc.ClientContext(ctx, rp.httpClient)

	// An already-expired token makes the token source refresh right away.
	tok, err := rp.oauth2Cfg.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refreshToken,
		Expiry:       time.Unix(1, 0),
	}).Token()
	if err != nil {
		var rerr *oauth2.RetrieveError
		if errors.As(err, &rerr) && rerr.ErrorCode == "invalid_grant" {
			return sso.Subject[Payload]{}, "token-refresh", fmt.Errorf("%w: %w", ErrRefreshRejected, err)
		}

		return sso.Subject[Payload]{}, "token-refresh", fmt.Errorf("refresh token grant: %w", err)
	}

	next := tok.RefreshToken
	if next == "" {
		next = refreshToken
	}

	sub, stage, err := rp.subjectFromRefresh(ctx, tok, next, expectedExternalID)
	if err != nil {
		return sso.Subject[Payload]{}, stage, &RefreshFailedError{RefreshToken: next, Err: err}
	}

	return sub, "", nil
}

// subjectFromRefresh verifies a refreshed token response and builds its
// subject; next is the refresh token to store.
func (rp *RP) subjectFromRefresh(ctx context.Context, tok *oauth2.Token, next, expectedExternalID string) (sso.Subject[Payload], string, error) {
	var (
		idToken *gooidc.IDToken
		err     error
	)

	rawIDToken, _ := tok.Extra("id_token").(string)
	if rawIDToken != "" {
		// A refreshed ID token carries no nonce (OIDC Core §12.2).
		idToken, err = rp.verifier.Verify(ctx, rawIDToken)
		if err != nil {
			return sso.Subject[Payload]{}, "verify-id-token", fmt.Errorf("verify refreshed id token: %w", err)
		}

		if rp.issuerValidator != nil {
			if err := rp.issuerValidator(idToken.Issuer); err != nil {
				return sso.Subject[Payload]{}, "issuer-validation", fmt.Errorf("validate refreshed issuer: %w", err)
			}
		}
	}

	var userInfo map[string]any

	if rp.fetchUserInfo || idToken == nil {
		ui, err := rp.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			return sso.Subject[Payload]{}, "userinfo", fmt.Errorf("userinfo: %w", err)
		}

		if idToken != nil && ui.Subject != idToken.Subject {
			return sso.Subject[Payload]{}, "userinfo-sub-mismatch", errors.New("userinfo sub != id token sub")
		}

		userInfo = map[string]any{}
		if err := ui.Claims(&userInfo); err != nil {
			return sso.Subject[Payload]{}, "userinfo-claims", fmt.Errorf("userinfo claims: %w", err)
		}
	}

	sub, err := buildSubject(idToken, rawIDToken, oauthToken{
		AccessToken:  tok.AccessToken,
		RefreshToken: next,
		Expiry:       tok.Expiry,
	}, userInfo, rp.claimMap)
	if err != nil {
		return sso.Subject[Payload]{}, "build-subject", err
	}

	if subtle.ConstantTimeCompare([]byte(sub.ExternalID), []byte(expectedExternalID)) != 1 {
		return sso.Subject[Payload]{}, "subject-mismatch", errors.New("refreshed subject differs from the session's subject")
	}

	return sub, "", nil
}
