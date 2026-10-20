package native

import (
	"context"
	"errors"
	"net/http"
	"time"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/oidc"
)

// maxRotateAttempts bounds the retries after a lost compare-and-swap.
const maxRotateAttempts = 3

// refreshWorkTimeout bounds a refresh's store and IdP work, which runs
// detached from the request so a client hang-up cannot interrupt it
// half-way.
const refreshWorkTimeout = 30 * time.Second

// refreshTokenGrant redeems a refresh token "<sessionID>.<secret>".
//
// The current secret is rotated before the IdP is called: the rotation is
// claimed with a compare-and-swap on the stored hash, so of concurrent
// requests with the same token exactly one calls the IdP. The others find
// their secret as the previous one and, inside the rotation grace window,
// get a fresh token set without an IdP call. A transient failure after
// the claim rolls the secret back, so the app's retry with the same token
// is not mistaken for reuse; if a grace hit rotated meanwhile, the retry
// still passes as a grace hit inside the window.
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

	for range maxRotateAttempts {
		s, err := b.store.GetSession(ctx, id)
		if errors.Is(err, ErrNotFound) {
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
		case h == s.RefreshHash:
			done = g.rotate(ctx, s, h)
		case b.inGrace(s, h):
			done = g.graceRotate(ctx, s)
		default:
			g.deleteSession(ctx, s.ID)
			g.fail(ctx, http.StatusBadRequest, errInvalidGrant, "token-reused", "refresh token reused", nil)

			return
		}

		if done {
			return
		}
	}

	g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "rotate-conflict", "concurrent refresh, retry", nil)
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
	if err := g.b.store.DeleteSession(ctx, id); err != nil {
		g.b.logError(g.r, "native-token-store-delete-session", err)
	}
}

// rotate handles the current secret: claim the rotation, refresh at the
// IdP, authenticate, mint, persist. It returns false when the claim lost a
// race and the caller should re-read the session.
//
// Once the IdP has answered with a refresh token, that token is stored on
// every exit path: the IdP may already have retired the old one. The work
// runs detached from the request, so an app that hangs up mid-refresh gets
// a clean rollback instead of a half-done rotation.
func (g *refreshGrant) rotate(reqCtx context.Context, s Session, h string) bool {
	b := g.b
	now := b.now()

	ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), refreshWorkTimeout)
	defer cancel()

	newSecret, err := randomToken(32)
	if err != nil {
		g.fail(ctx, http.StatusInternalServerError, errServerError, "random", "", err)
		return true
	}

	claimed := s
	claimed.RefreshHash = hashToken(newSecret)
	claimed.PreviousRefreshHash = h
	claimed.RotatedAt = now

	if err := b.store.RotateSession(ctx, claimed, h); errors.Is(err, ErrConflict) {
		return false
	} else if err != nil {
		g.fail(ctx, http.StatusInternalServerError, errServerError, "store-rotate-session", "", err)
		return true
	}

	// rollback undoes the claim so the app's retry with the same token
	// still matches, and keeps a new IdP token (nil: none was issued).
	rollback := func(idpToken *EncryptedToken) {
		orig := s
		if idpToken != nil {
			orig.IDPRefreshToken = *idpToken
		}

		err := b.store.RotateSession(ctx, orig, claimed.RefreshHash)

		switch {
		case err == nil:
		case errors.Is(err, ErrConflict):
			// a concurrent grace hit rotated meanwhile: its secret stands,
			// but the session must still get the new IdP token
			if idpToken != nil {
				g.storeIDPToken(ctx, s.ID, *idpToken)
			}
		default:
			b.logError(g.r, "native-token-rollback", err)
		}
	}

	idpToken, err := b.sealer.open(s.IDPRefreshToken, sealAAD(s.Subject.ExternalID))
	if err != nil {
		rollback(nil)
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
				rollback(&sealed)
			} else {
				rollback(nil)
				b.logError(g.r, "native-token-seal-idp-token", serr)
			}
		} else {
			rollback(nil)
		}

		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "idp-refresh", "identity provider unavailable", err)

		return true
	}

	sealed, err := b.sealer.seal(sub.Raw.RefreshToken, sealAAD(sub.ExternalID))
	if err != nil {
		rollback(nil)
		g.fail(ctx, http.StatusInternalServerError, errServerError, "seal-idp-token", "", err)

		return true
	}

	attrs, err := b.hooks.Authenticate(ctx, g.r, sub)
	if err != nil {
		rollback(&sealed)
		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "authenticate", "", err)

		return true
	}

	final := claimed
	applyRefresh(&final, sub, attrs, sealed, now)

	resp, err := b.issue(ctx, final, newSecret)
	if err != nil {
		rollback(&sealed)
		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "mint", "", err)

		return true
	}

	// the app hung up: it never sees resp, so do not move it on to a
	// secret it does not know
	if reqCtx.Err() != nil {
		rollback(&sealed)
		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "client-gone", "", reqCtx.Err())

		return true
	}

	resp, err = g.persist(ctx, final, claimed.RefreshHash, resp, sub, attrs, sealed, now)
	if err != nil {
		rollback(&sealed)
		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "store-persist", "", err)

		return true
	}

	g.succeed(ctx, resp)

	return true
}

// persist stores the refreshed session. When a concurrent grace hit rotated
// the secret meanwhile, the refreshed data goes onto the latest state and
// the secret is rotated once more, so this response, which completes last,
// carries the current refresh token. The previous secret and its window
// are kept, so a late duplicate of the original token still passes.
func (g *refreshGrant) persist(ctx context.Context, final Session, expected string, resp tokenResponse, sub sso.Subject[oidc.Payload], attrs Attributes, sealed EncryptedToken, now time.Time) (tokenResponse, error) {
	for range maxRotateAttempts {
		err := g.b.store.RotateSession(ctx, final, expected)
		if !errors.Is(err, ErrConflict) {
			return resp, err
		}

		cur, err := g.b.store.GetSession(ctx, final.ID)
		if err != nil {
			return resp, err
		}

		secret, err := randomToken(32)
		if err != nil {
			return resp, err
		}

		next := cur
		applyRefresh(&next, sub, attrs, sealed, now)
		next.RefreshHash = hashToken(secret)

		if resp, err = g.b.issue(ctx, next, secret); err != nil {
			return resp, err
		}

		final, expected = next, cur.RefreshHash
	}

	return resp, errors.New("persist refreshed session: too many concurrent rotations")
}

// storeIDPToken writes a new IdP refresh token onto the session's current
// state, whatever its secret.
func (g *refreshGrant) storeIDPToken(ctx context.Context, id string, idpToken EncryptedToken) {
	for range maxRotateAttempts {
		cur, err := g.b.store.GetSession(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return
		} else if err != nil {
			g.b.logError(g.r, "native-token-store-idp-token", err)
			return
		}

		cur.IDPRefreshToken = idpToken

		err = g.b.store.RotateSession(ctx, cur, cur.RefreshHash)
		if err == nil {
			return
		} else if !errors.Is(err, ErrConflict) {
			g.b.logError(g.r, "native-token-store-idp-token", err)
			return
		}
	}

	g.b.logError(g.r, "native-token-store-idp-token", errors.New("too many concurrent rotations"))
}

// graceRotate handles the previous secret inside the grace window: a
// concurrent duplicate of a refresh in flight. It rotates the current
// secret and issues a fresh token set without calling the IdP; the
// previous secret and the window it runs in are left as they are.
func (g *refreshGrant) graceRotate(ctx context.Context, s Session) bool {
	b := g.b
	now := b.now()

	newSecret, err := randomToken(32)
	if err != nil {
		g.fail(ctx, http.StatusInternalServerError, errServerError, "random", "", err)
		return true
	}

	// PreviousRefreshHash and RotatedAt stay: further duplicates of the
	// same token must still pass, and the window must not extend
	next := s
	next.RefreshHash = hashToken(newSecret)
	next.LastUsedAt = now

	if err := b.store.RotateSession(ctx, next, s.RefreshHash); errors.Is(err, ErrConflict) {
		return false
	} else if err != nil {
		g.fail(ctx, http.StatusInternalServerError, errServerError, "store-rotate-session", "", err)
		return true
	}

	resp, err := b.issue(ctx, next, newSecret)
	if err != nil {
		if rerr := b.store.RotateSession(ctx, s, next.RefreshHash); rerr != nil && !errors.Is(rerr, ErrConflict) {
			b.logError(g.r, "native-token-rollback", rerr)
		}

		g.fail(ctx, http.StatusServiceUnavailable, errTemporarilyUnavailable, "mint", "", err)

		return true
	}

	g.succeed(ctx, resp)

	return true
}

func applyRefresh(s *Session, sub sso.Subject[oidc.Payload], attrs Attributes, sealed EncryptedToken, now time.Time) {
	s.Subject = projectSubject(sub)
	s.Attributes = cloneAttributes(attrs)
	s.IDPRefreshToken = sealed
	s.LastUsedAt = now
}
