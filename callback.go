package sso

import (
	"context"
	"net/http"
)

// OnAuthenticated fires after a successful authentication round-trip.
// The consumer is responsible for persisting whatever session
// representation (cookie, JWT, server-side record, ...) it needs.
//
// Returning a non-nil error aborts the login flow: the adapter will not
// perform its post-authentication redirect and will surface the error
// as HTTP 500 to the caller.
type OnAuthenticated[T any] func(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	sub Subject[T],
) error

// OnLogout fires when the logout handler is invoked. The consumer should
// destroy its session. Returning a non-nil error aborts logout with HTTP
// 500 and skips any IdP-side single-logout redirect.
type OnLogout func(ctx context.Context, w http.ResponseWriter, r *http.Request) error

// ErrorLogger receives runtime errors encountered while processing an
// SSO HTTP request. The msg argument is a short stable identifier for
// the failing stage (e.g. "token-exchange", "verify-id-token",
// "on-authenticated"). HTTP responses from the adapters stay generic;
// this callback exists so consumers can route the underlying cause to
// their own structured logger without exposing internals to the
// browser.
type ErrorLogger func(r *http.Request, msg string, err error)
