package native

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/oidc"
	"github.com/foomo/gosso/oidc/native/repository"
	"github.com/foomo/gosso/oidc/native/repository/store"
)

const (
	// maxRotateAttempts bounds the retries after a lost compare-and-swap.
	maxRotateAttempts = 3
	// refreshWorkTimeout bounds a refresh's store and IdP work, which runs
	// detached from the request so a client hang-up cannot interrupt it
	// half-way.
	refreshWorkTimeout = 30 * time.Second
	// refreshLeaseMargin keeps a lease alive well past refreshWorkTimeout,
	// so it does not expire under a refresh still at work: a hook that
	// overruns its context, or broker instances whose clocks differ (a
	// lease is checked against the reading instance's clock). Skew
	// beyond the margin can let a second refresh take over.
	refreshLeaseMargin = refreshWorkTimeout
	// leasePollInterval is how often a waiting refresh re-reads the session.
	leasePollInterval = 50 * time.Millisecond
	// maxCurrentHashes bounds the secrets of one generation: the
	// rotation's own plus those of concurrent duplicates.
	maxCurrentHashes = 8
	// maxRetiredHashes bounds the history kept for reuse detection.
	maxRetiredHashes = 32
)

var (
	errLeaseLost        = errors.New("refresh lease lost")
	errTooManyConflicts = errors.New("too many concurrent session updates")
)

// refreshTokenGrant redeems a refresh token "<sessionID>.<secret>".
//
// The secret's hash decides what happens:
//
//   - current: the refresh takes a lease on the session, refreshes at the
//     IdP and rotates; the new secret becomes the current generation, the
//     old one the previous generation. While a lease is held, refreshes
//     with a current secret wait for it, so the IdP is called once.
//   - previous, within the rotation grace window: a concurrent or retried
//     duplicate. It gets a fresh secret added to the current generation,
//     valid alongside the rotation's own, without an IdP call. The window
//     starts when the rotation is stored, not when it began.
//   - previous outside the window, or retired: reuse of a rotated token,
//     which ends the session (OAuth 2.0 Security BCP §4.14).
//   - unknown: invalid_grant. The session is left alone, so knowing a
//     session ID is not enough to end it.
func (b *Broker) refreshTokenGrant(w http.ResponseWriter, r *http.Request, rp *oidc.RP, client Client) {
	ctx := r.Context()

	g := refreshGrant{b: b, w: w, r: r, rp: rp, client: client}

	token := r.PostForm.Get("refresh_token")
	if token == "" {
		g.fail(ctx, http.StatusBadRequest, errInvalidRequest, "missing-parameter", "refresh_token is required", nil)
		return
	}

	id, secret, ok := cutToken(token)
	if !ok {
		g.fail(ctx, http.StatusBadRequest, errInvalidGrant, "malformed-token", "refresh token invalid", nil)
		return
	}

	h := hashToken(secret)

	// one deadline for all waits on other refreshes' leases
	waitCtx, cancelWait := context.WithTimeout(ctx, refreshWorkTimeout+refreshLeaseMargin)
	defer cancelWait()

	for attempt := 0; attempt < maxRotateAttempts; {
		s, err := b.sessions.Get(ctx, id)
		if errors.Is(err, repository.ErrNotFound) {
			g.fail(ctx, http.StatusBadRequest, errInvalidGrant, "session-unknown", "refresh token invalid", nil)
			return
		} else if err != nil {
			g.fail(ctx, http.StatusInternalServerError, errServerError, "store-get-session", "", err)
			return
		}

		if s.ClientID != client.ID {
			g.fail(ctx, http.StatusBadRequest, errInvalidGrant, "client-mismatch", "refresh token was issued to another client", nil)
			return
		}

		if b.now().After(s.ExpiresAt) {
			g.deleteSession(ctx, s.ID)
			g.fail(ctx, http.StatusBadRequest, errInvalidGrant, "session-expired", "session expired", nil)

			return
		}

		var done bool

		switch {
		case slices.Contains(s.RefreshHashes, h) && b.leased(s):
			// another refresh is at the IdP: wait for it, then look again
			if !g.waitForLease(waitCtx, s) {
				return
			}

			continue
		case slices.Contains(s.RefreshHashes, h):
			done = g.rotate(ctx, s)
		case b.inGrace(s, h):
			done = g.graceHit(ctx, s)
		case slices.Contains(s.PreviousRefreshHashes, h), slices.Contains(s.RetiredRefreshHashes, h):
			g.deleteSession(ctx, s.ID)
			g.fail(ctx, http.StatusBadRequest, errInvalidGrant, "token-reused", "refresh token reused", nil)

			return
		default:
			g.fail(ctx, http.StatusBadRequest, errInvalidGrant, "secret-unknown", "refresh token invalid", nil)
			return
		}

		if done {
			return
		}

		attempt++
	}

	g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "rotate-conflict", "concurrent refresh, retry", nil)
}

// leased reports whether a refresh currently holds s at the IdP.
func (b *Broker) leased(s store.Session) bool {
	return s.RefreshLease != "" && b.now().Before(s.RefreshLeaseUntil)
}

// refreshGrant carries one refresh request.
type refreshGrant struct {
	b      *Broker
	w      http.ResponseWriter
	r      *http.Request
	rp     *oidc.RP
	client Client
}

func (g *refreshGrant) fail(ctx context.Context, status int, code, stage, description string, err error) {
	g.b.tokenFailed(ctx, g.r, grantRefreshToken, stage, err)
	writeError(g.w, status, code, description)
}

func (g *refreshGrant) succeed(ctx context.Context, resp tokenResponse) {
	tokenSucceeded(ctx, grantRefreshToken)
	writeJSON(g.w, http.StatusOK, resp)
}

func (g *refreshGrant) deleteSession(ctx context.Context, id string) {
	if err := g.b.sessions.Delete(ctx, id); err != nil {
		g.b.logError(g.r, "native-token-store-delete-session", err)
	}
}

// waitForLease polls until the lease held on s is released or expires.
// It reports false, after answering, when the wait gave up; ctx carries
// the request's overall wait deadline.
func (g *refreshGrant) waitForLease(ctx context.Context, s store.Session) bool {
	ticker := time.NewTicker(leasePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "lease-wait", "refresh in progress, retry", ctx.Err())
			return false
		case <-ticker.C:
		}

		cur, err := g.b.sessions.Get(ctx, s.ID)
		if errors.Is(err, repository.ErrNotFound) {
			g.fail(ctx, http.StatusBadRequest, errInvalidGrant, "session-unknown", "refresh token invalid", nil)
			return false
		} else if err != nil {
			g.fail(ctx, http.StatusInternalServerError, errServerError, "store-get-session", "", err)
			return false
		}

		if cur.RefreshLease != s.RefreshLease || !g.b.leased(cur) {
			return true
		}
	}
}

// rotate handles a current secret: take the lease, refresh at the IdP,
// store the rotation, then mint. It reports false when the lease was
// lost to a concurrent request, which the caller retries.
//
// Until the rotation is stored the secrets stay as they are, so every
// failure leaves the app's token valid for a retry. Once the IdP has
// answered with a refresh token, that token is stored on every exit path:
// the IdP may already have retired the old one. The work runs detached
// from the request, so an app that hangs up mid-refresh cannot leave it
// half-done.
func (g *refreshGrant) rotate(reqCtx context.Context, s store.Session) bool {
	b := g.b

	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), refreshWorkTimeout)
	defer cancel()

	lease, err := randomToken(16)
	if err != nil {
		g.fail(ctx, http.StatusInternalServerError, errServerError, "random", "", err)
		return true
	}

	claimed := s
	claimed.RefreshLease = lease
	claimed.RefreshLeaseUntil = b.now().Add(refreshWorkTimeout + refreshLeaseMargin)

	if err := b.sessions.Rotate(ctx, claimed); errors.Is(err, repository.ErrConflict) {
		return false
	} else if err != nil {
		g.fail(ctx, http.StatusInternalServerError, errServerError, "store-claim-session", "", err)
		return true
	}

	// release gives the lease back, keeping a new IdP token (nil: none
	// was issued); the secrets are untouched.
	release := func(idpToken *store.EncryptedToken) {
		_, err := g.update(ctx, s.ID, lease, func(cur *store.Session) {
			clearLease(cur)

			if idpToken != nil {
				cur.IDPRefreshToken = *idpToken
			}
		})

		switch {
		case errors.Is(err, errLeaseLost) && idpToken != nil:
			// another refresh took over after the lease expired: keep the
			// IdP's new token anyway, unless that refresh stored a newer one
			g.storeIDPToken(ctx, s.ID, s.IDPRefreshToken, *idpToken)
		case err != nil && !errors.Is(err, repository.ErrNotFound) && !errors.Is(err, errLeaseLost):
			b.logError(g.r, "native-token-release", err)
		}
	}

	idpToken, err := b.sealer.open(s.IDPRefreshToken, sealAAD(s.Subject.ExternalID))
	if err != nil {
		release(nil)
		g.fail(ctx, http.StatusInternalServerError, errServerError, "decrypt-idp-token", "", err)

		return true
	}

	sub, err := g.rp.Refresh(ctx, idpToken, s.Subject.ExternalID)
	if errors.Is(err, oidc.ErrRefreshRejected) {
		g.deleteSession(ctx, s.ID)
		g.fail(ctx, http.StatusBadRequest, errInvalidGrant, "idp-rejected", "refresh rejected by identity provider", err)

		return true
	} else if err != nil {
		// the grant may have succeeded before a later step failed
		if rfe, ok := errors.AsType[*oidc.RefreshFailedError](err); ok {
			if sealed, serr := b.sealer.seal(rfe.RefreshToken, sealAAD(s.Subject.ExternalID)); serr == nil {
				release(&sealed)
			} else {
				release(nil)
				b.logError(g.r, "native-token-seal-idp-token", serr)
			}
		} else {
			release(nil)
		}

		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "idp-refresh", "identity provider unavailable", err)

		return true
	}

	sealed, err := b.sealer.seal(sub.Raw.RefreshToken, sealAAD(sub.ExternalID))
	if err != nil {
		release(nil)
		g.fail(ctx, http.StatusInternalServerError, errServerError, "seal-idp-token", "", err)

		return true
	}

	attrs, err := b.hooks.Authenticate(ctx, g.r, sub)
	if err != nil {
		release(&sealed)
		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "authenticate", "", err)

		return true
	}

	// a hook that ignored the deadline: stop before the lease runs out
	if ctx.Err() != nil {
		release(&sealed)
		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "work-timeout", "", ctx.Err())

		return true
	}

	// the app hung up: it would never see a new secret, so keep its old one
	if reqCtx.Err() != nil {
		release(&sealed)
		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "client-gone", "", reqCtx.Err())

		return true
	}

	secret, err := randomToken(32)
	if err != nil {
		release(&sealed)
		g.fail(ctx, http.StatusInternalServerError, errServerError, "random", "", err)

		return true
	}

	newHash := hashToken(secret)

	var before store.Session

	final, err := g.update(ctx, s.ID, lease, func(cur *store.Session) {
		before = *cur
		now := b.now()

		applyRefresh(cur, sub, attrs, sealed, now)
		retire(cur, newHash, now)
		clearLease(cur)
	})

	switch {
	case errors.Is(err, repository.ErrNotFound):
		// revoked or rejected while this refresh was at the IdP
		g.fail(ctx, http.StatusBadRequest, errInvalidGrant, "session-unknown", "refresh token invalid", nil)
		return true
	case err != nil:
		release(&sealed)
		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "store-persist", "", err)

		return true
	}

	resp, err := b.issue(ctx, final, secret)
	if err != nil {
		g.unrotate(ctx, before, final, newHash)
		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "mint", "", err)

		return true
	}

	g.succeed(ctx, resp)

	return true
}

// unrotate takes back a stored rotation whose response never went out,
// so the app's old secret is current again. The refreshed subject,
// attributes and IdP token stay. A grace hit that joined the new
// generation meanwhile has handed out a token of it, which then wins.
func (g *refreshGrant) unrotate(ctx context.Context, before, rotated store.Session, newHash string) {
	_, err := g.update(ctx, rotated.ID, "", func(cur *store.Session) {
		if !slices.Equal(cur.RefreshHashes, []string{newHash}) {
			return
		}

		cur.RefreshHashes = before.RefreshHashes
		cur.PreviousRefreshHashes = before.PreviousRefreshHashes
		cur.RotatedAt = before.RotatedAt
		cur.RetiredRefreshHashes = before.RetiredRefreshHashes
	})
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		g.b.logError(g.r, "native-token-unrotate", err)
	}
}

// storeIDPToken stores idpToken on the session if its IdP token is still
// the one the refresh started from, so a newer one is never overwritten.
func (g *refreshGrant) storeIDPToken(ctx context.Context, id string, from, idpToken store.EncryptedToken) {
	_, err := g.update(ctx, id, "", func(cur *store.Session) {
		if cur.IDPRefreshToken.KeyID == from.KeyID && bytes.Equal(cur.IDPRefreshToken.Ciphertext, from.Ciphertext) {
			cur.IDPRefreshToken = idpToken
		}
	})
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		g.b.logError(g.r, "native-token-store-idp-token", err)
	}
}

// graceHit handles a previous secret inside the grace window: a concurrent
// or retried duplicate of a stored rotation. It adds a fresh secret to the
// current generation, valid alongside the rotation's own, and issues a
// token set without calling the IdP. The previous generation and its
// window are left as they are.
func (g *refreshGrant) graceHit(ctx context.Context, s store.Session) bool {
	b := g.b

	if len(s.RefreshHashes) >= maxCurrentHashes {
		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "grace-full", "too many concurrent refreshes, retry", nil)
		return true
	}

	secret, err := randomToken(32)
	if err != nil {
		g.fail(ctx, http.StatusInternalServerError, errServerError, "random", "", err)
		return true
	}

	newHash := hashToken(secret)

	next := s
	next.RefreshHashes = append(slices.Clone(s.RefreshHashes), newHash)
	next.LastUsedAt = b.now()

	if err := b.sessions.Rotate(ctx, next); errors.Is(err, repository.ErrConflict) {
		return false
	} else if err != nil {
		g.fail(ctx, http.StatusInternalServerError, errServerError, "store-rotate-session", "", err)
		return true
	}

	next.Version++

	resp, err := b.issue(ctx, next, secret)
	if err != nil {
		// the secret never went out: drop it again
		if _, uerr := g.update(ctx, s.ID, "", func(cur *store.Session) {
			cur.RefreshHashes = slices.DeleteFunc(cur.RefreshHashes, func(h string) bool { return h == newHash })
		}); uerr != nil && !errors.Is(uerr, repository.ErrNotFound) {
			b.logError(g.r, "native-token-drop-secret", uerr)
		}

		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "mint", "", err)

		return true
	}

	g.succeed(ctx, resp)

	return true
}

// update applies fn to the session's latest state and stores it, retrying
// lost compare-and-swaps. With a non-empty lease it fails with
// errLeaseLost unless the session still carries that lease.
func (g *refreshGrant) update(ctx context.Context, id, lease string, fn func(*store.Session)) (store.Session, error) {
	for range maxRotateAttempts {
		cur, err := g.b.sessions.Get(ctx, id)
		if err != nil {
			return store.Session{}, err
		}

		if lease != "" && cur.RefreshLease != lease {
			return store.Session{}, errLeaseLost
		}

		fn(&cur)

		err = g.b.sessions.Rotate(ctx, cur)
		if err == nil {
			cur.Version++
			return cur, nil
		} else if !errors.Is(err, repository.ErrConflict) {
			return store.Session{}, err
		}
	}

	return store.Session{}, errTooManyConflicts
}

func applyRefresh(s *store.Session, sub sso.Subject[oidc.Payload], attrs store.Attributes, sealed store.EncryptedToken, now time.Time) {
	s.Subject = projectSubject(sub)
	s.Attributes = cloneAttributes(attrs)
	s.IDPRefreshToken = sealed
	s.LastUsedAt = now
}

// retire makes newHash the only current secret: the current generation
// becomes the previous one, accepted for the grace window from now, and
// the previous one joins the bounded retired history.
func retire(s *store.Session, newHash string, now time.Time) {
	retired := slices.Concat(s.RetiredRefreshHashes, s.PreviousRefreshHashes)
	if n := len(retired) - maxRetiredHashes; n > 0 {
		retired = retired[n:]
	}

	s.RetiredRefreshHashes = retired
	s.PreviousRefreshHashes = s.RefreshHashes
	s.RefreshHashes = []string{newHash}
	s.RotatedAt = now
}

func clearLease(s *store.Session) {
	s.RefreshLease = ""
	s.RefreshLeaseUntil = time.Time{}
}
