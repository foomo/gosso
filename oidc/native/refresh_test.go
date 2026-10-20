package native

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/foomo/gosso/internal/fakeidp"
)

func sessionOf(t *testing.T, f *fixture, rt string) (Session, error) {
	t.Helper()

	id, _, ok := cutToken(rt)
	require.True(t, ok, rt)

	return f.store.GetSession(t.Context(), id)
}

func TestToken_Refresh(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	rt := f.fullLogin(t)

	before, err := sessionOf(t, f, rt)
	require.NoError(t, err)

	idpBefore, err := f.broker.sealer.open(before.IDPRefreshToken, sealAAD("alice"))
	require.NoError(t, err)

	f.clock.Advance(time.Minute)

	res := f.refresh(t, rt)
	require.Equal(t, http.StatusOK, res.status, "%v", res.body)
	assert.Equal(t, "Bearer", res.str("token_type"))
	assert.Equal(t, "no-store", res.header.Get("Cache-Control"))

	next := res.str("refresh_token")
	assert.NotEqual(t, rt, next)
	assert.NotEmpty(t, res.str("access_token"))

	id, _, _ := cutToken(rt)
	nextID, _, _ := cutToken(next)
	assert.Equal(t, id, nextID, "same session")

	after, err := sessionOf(t, f, next)
	require.NoError(t, err)

	_, oldSecret, _ := cutToken(rt)
	assert.Equal(t, hashToken(oldSecret), after.PreviousRefreshHash, "old token is in grace")
	assert.True(t, after.RotatedAt.Equal(f.clock.Now()))
	assert.True(t, after.LastUsedAt.Equal(f.clock.Now()))
	assert.True(t, after.ExpiresAt.Equal(before.ExpiresAt), "absolute lifetime unchanged")

	idpAfter, err := f.broker.sealer.open(after.IDPRefreshToken, sealAAD("alice"))
	require.NoError(t, err)
	assert.NotEqual(t, idpBefore, idpAfter, "IdP rotated its refresh token")
	assert.True(t, strings.HasPrefix(idpAfter, "rt-"), idpAfter)

	subs := f.authenticatedSubjects()
	require.Len(t, subs, 2, "login + refresh")
	assert.Equal(t, "alice", subs[1].ExternalID)
	assert.Equal(t, idpAfter, subs[1].Raw.RefreshToken)
	assert.Equal(t, Attributes{"email": "alice@example.com", "logins": "xx"}, after.Attributes)

	// the old token still works inside the grace window
	assert.Equal(t, http.StatusOK, f.refresh(t, rt).status)
}

func TestToken_RefreshReuseOutsideGrace(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	a := f.fullLogin(t)

	res := f.refresh(t, a)
	require.Equal(t, http.StatusOK, res.status)
	b := res.str("refresh_token")

	f.clock.Advance(11 * time.Second)

	assertOAuthError(t, f.refresh(t, a), http.StatusBadRequest, errInvalidGrant)

	_, err := sessionOf(t, f, b)
	require.ErrorIs(t, err, ErrNotFound, "reuse revokes the session")
	assertOAuthError(t, f.refresh(t, b), http.StatusBadRequest, errInvalidGrant)
}

func TestToken_RefreshConcurrent(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	rt := f.fullLogin(t)
	before := idpTokenOf(t, f, rt)
	f.idp.SetRefreshDelay(200 * time.Millisecond)

	var (
		wg      sync.WaitGroup
		results [2]tokenResult
	)

	for i := range results {
		wg.Go(func() { results[i] = f.refresh(t, rt) })
	}

	wg.Wait()

	for _, r := range results {
		assert.Equal(t, http.StatusOK, r.status, "%v", r.body)
	}

	assert.Equal(t, 1, f.idp.RefreshCalls())

	// the session survived and holds the IdP's rotated token
	assert.NotEqual(t, before, idpTokenOf(t, f, rt))
}

func TestToken_RefreshRejectedByIdP(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	rt := f.fullLogin(t)
	f.idp.SetRefreshBehaviour(fakeidp.RefreshReject)

	assertOAuthError(t, f.refresh(t, rt), http.StatusBadRequest, errInvalidGrant)

	_, err := sessionOf(t, f, rt)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestToken_RefreshTransientFailureKeepsToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	rt := f.fullLogin(t)
	f.idp.SetRefreshBehaviour(fakeidp.RefreshServerError)

	assertOAuthError(t, f.refresh(t, rt), http.StatusServiceUnavailable, errTemporarilyUnavailable)

	f.clock.Advance(5 * time.Minute)
	f.idp.SetRefreshBehaviour(fakeidp.RefreshRotate)

	res := f.refresh(t, rt)
	assert.Equal(t, http.StatusOK, res.status, "%v", res.body)
}

func TestToken_RefreshAuthenticateFails(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	rt := f.fullLogin(t)
	f.setAuthenticateErr(errHook)

	assertOAuthError(t, f.refresh(t, rt), http.StatusServiceUnavailable, errTemporarilyUnavailable)

	f.clock.Advance(time.Minute)
	f.setAuthenticateErr(nil)

	// the IdP rotated its refresh token during the failed attempt and
	// retired the old one; the broker must have kept the new one
	assert.Equal(t, http.StatusOK, f.refresh(t, rt).status)
	assert.Equal(t, 2, f.idp.RefreshCalls())
}

func TestToken_RefreshMintFails(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	rt := f.fullLogin(t)
	f.setMintErr(errHook)

	assertOAuthError(t, f.refresh(t, rt), http.StatusServiceUnavailable, errTemporarilyUnavailable)

	f.clock.Advance(time.Minute)
	f.setMintErr(nil)
	assert.Equal(t, http.StatusOK, f.refresh(t, rt).status)
}

func TestToken_RefreshSubjectChanged(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	rt := f.fullLogin(t)
	f.idp.SetRefreshBehaviour(fakeidp.RefreshOtherSubject)

	assertOAuthError(t, f.refresh(t, rt), http.StatusServiceUnavailable, errTemporarilyUnavailable)

	_, err := sessionOf(t, f, rt)
	require.NoError(t, err, "session kept")
}

func TestToken_RefreshExpiredSession(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	rt := f.fullLogin(t)
	f.clock.Advance(defaultSessionTTL + time.Second)

	assertOAuthError(t, f.refresh(t, rt), http.StatusBadRequest, errInvalidGrant)

	_, err := sessionOf(t, f, rt)
	require.ErrorIs(t, err, ErrNotFound)
	assert.Zero(t, f.idp.RefreshCalls())
}

func TestToken_RefreshWrongClient(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	rt := f.fullLogin(t)

	res := f.post(t, "/app/token", map[string][]string{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
		"client_id":     {clientAndroid},
	})
	assertOAuthError(t, res, http.StatusBadRequest, errInvalidGrant)
	assert.Zero(t, f.idp.RefreshCalls())
}

func TestToken_RefreshMalformed(t *testing.T) {
	t.Parallel()

	f := newFixture(t)

	assertOAuthError(t, f.refresh(t, "abc"), http.StatusBadRequest, errInvalidGrant)
	assertOAuthError(t, f.refresh(t, "."), http.StatusBadRequest, errInvalidGrant)
	assertOAuthError(t, f.refresh(t, "unknown.secret"), http.StatusBadRequest, errInvalidGrant)
	assertOAuthError(t, f.refresh(t, ""), http.StatusBadRequest, errInvalidRequest)
}

// Every duplicate in a burst passes, not just the first: grace hits must
// not retire the token the burst started with.
func TestToken_RefreshConcurrentThree(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	rt := f.fullLogin(t)
	f.idp.SetRefreshDelay(200 * time.Millisecond)

	var (
		wg      sync.WaitGroup
		results [3]tokenResult
	)

	for i := range results {
		wg.Go(func() { results[i] = f.refresh(t, rt) })
		time.Sleep(50 * time.Millisecond) // the first reaches the IdP
	}

	wg.Wait()

	for _, r := range results {
		assert.Equal(t, http.StatusOK, r.status, "%v", r.body)
	}

	assert.Equal(t, 1, f.idp.RefreshCalls())

	_, err := sessionOf(t, f, rt)
	require.NoError(t, err, "session survived")
}

// A duplicate arriving after the primary completed still passes inside
// the window, and the primary's token stays current.
func TestToken_RefreshLateDuplicateAfterPersist(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	a := f.fullLogin(t)
	f.idp.SetRefreshDelay(200 * time.Millisecond)

	var (
		wg      sync.WaitGroup
		primary tokenResult
	)

	wg.Go(func() { primary = f.refresh(t, a) })

	time.Sleep(50 * time.Millisecond) // primary is at the IdP

	require.Equal(t, http.StatusOK, f.refresh(t, a).status)

	wg.Wait()
	require.Equal(t, http.StatusOK, primary.status, "%v", primary.body)

	late := f.refresh(t, a)
	require.Equal(t, http.StatusOK, late.status, "%v", late.body)

	f.idp.SetRefreshDelay(0)
	f.clock.Advance(11 * time.Second) // grace window closed

	res := f.refresh(t, late.str("refresh_token"))
	assert.Equal(t, http.StatusOK, res.status, "%v", res.body)
}

// Grace hits do not extend the window: it runs from the rotation.
func TestToken_RefreshGraceNotExtended(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	a := f.fullLogin(t)

	require.Equal(t, http.StatusOK, f.refresh(t, a).status)

	f.clock.Advance(6 * time.Second)
	require.Equal(t, http.StatusOK, f.refresh(t, a).status)

	f.clock.Advance(3 * time.Second)
	require.Equal(t, http.StatusOK, f.refresh(t, a).status)

	f.clock.Advance(2 * time.Second) // 11s after the rotation
	assertOAuthError(t, f.refresh(t, a), http.StatusBadRequest, errInvalidGrant)
}

// idpTokenOf returns the decrypted IdP refresh token of rt's session.
func idpTokenOf(t *testing.T, f *fixture, rt string) string {
	t.Helper()

	s, err := sessionOf(t, f, rt)
	require.NoError(t, err)

	idpRT, err := f.broker.sealer.open(s.IDPRefreshToken, sealAAD(s.Subject.ExternalID))
	require.NoError(t, err)

	return idpRT
}

// A grace hit rotates the secret while the primary request is at the IdP;
// the primary then fails in Authenticate. Its rollback conflicts, but the
// IdP's new refresh token must still be stored.
func TestToken_RefreshRollbackConflictKeepsIdPToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	a := f.fullLogin(t)
	before := idpTokenOf(t, f, a)

	f.idp.SetRefreshDelay(300 * time.Millisecond)
	f.setAuthenticateErr(errHook)

	var (
		wg      sync.WaitGroup
		primary tokenResult
	)

	wg.Go(func() { primary = f.refresh(t, a) })

	time.Sleep(100 * time.Millisecond) // primary is at the IdP

	grace := f.refresh(t, a)
	require.Equal(t, http.StatusOK, grace.status, "%v", grace.body)

	wg.Wait()
	assertOAuthError(t, primary, http.StatusServiceUnavailable, errTemporarilyUnavailable)

	c := grace.str("refresh_token")
	assert.NotEqual(t, before, idpTokenOf(t, f, c), "IdP's rotated token stored")

	f.idp.SetRefreshDelay(0)
	f.setAuthenticateErr(nil)
	f.clock.Advance(time.Minute)

	res := f.refresh(t, c)
	assert.Equal(t, http.StatusOK, res.status, "%v", res.body)
}

// After a rollback that conflicted with a grace hit, the app's retry with
// the original token passes as a grace hit instead of reuse.
func TestToken_RefreshRetryAfterRollbackConflict(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	a := f.fullLogin(t)

	f.idp.SetRefreshDelay(300 * time.Millisecond)
	f.setAuthenticateErr(errHook)

	var (
		wg      sync.WaitGroup
		primary tokenResult
	)

	wg.Go(func() { primary = f.refresh(t, a) })

	time.Sleep(100 * time.Millisecond) // primary is at the IdP

	require.Equal(t, http.StatusOK, f.refresh(t, a).status)

	wg.Wait()
	assertOAuthError(t, primary, http.StatusServiceUnavailable, errTemporarilyUnavailable)

	f.setAuthenticateErr(nil)

	res := f.refresh(t, a)
	assert.Equal(t, http.StatusOK, res.status, "%v", res.body)
}

func TestToken_RefreshPersistFailureKeepsToken(t *testing.T) {
	t.Parallel()

	// RotateSession #1 is the claim, #2 the persist of the refreshed state
	f := newFixtureWithStore(t, func(m *MemoryStore) Store { return &faultyStore{MemoryStore: m, failAt: 2} })
	a := f.fullLogin(t)

	assertOAuthError(t, f.refresh(t, a), http.StatusServiceUnavailable, errTemporarilyUnavailable)

	f.clock.Advance(5 * time.Minute)

	res := f.refresh(t, a)
	assert.Equal(t, http.StatusOK, res.status, "%v", res.body)
}

func TestToken_RefreshClientGoneKeepsToken(t *testing.T) {
	t.Parallel()

	f := newFixtureWithStore(t, func(m *MemoryStore) Store { return ctxStore{MemoryStore: m} })
	a := f.fullLogin(t)

	s, err := sessionOf(t, f, a)
	require.NoError(t, err)

	before := idpTokenOf(t, f, a)

	f.idp.SetRefreshDelay(300 * time.Millisecond)

	// the app gives up while the broker is at the IdP
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.server.URL+"/app/token", strings.NewReader(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {a},
		"client_id":     {clientIOS},
	}.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}

	require.Error(t, err)

	// the broker finishes in the background: secret rolled back, IdP token kept
	require.Eventually(t, func() bool {
		cur, err := f.store.GetSession(t.Context(), s.ID)
		return err == nil && cur.RefreshHash == s.RefreshHash && idpTokenOf(t, f, a) != before
	}, 3*time.Second, 20*time.Millisecond)

	f.idp.SetRefreshDelay(0)
	f.clock.Advance(5 * time.Minute)

	res := f.refresh(t, a)
	assert.Equal(t, http.StatusOK, res.status, "%v", res.body)
}

func TestToken_RefreshUserInfoFailureKeepsToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	a := f.fullLogin(t)

	// the IdP rotates, returns no ID token, and UserInfo is down
	f.idp.SetRefreshBehaviour(fakeidp.RefreshNoIDToken)
	f.idp.SetUserInfoError(true)

	assertOAuthError(t, f.refresh(t, a), http.StatusServiceUnavailable, errTemporarilyUnavailable)

	f.idp.SetUserInfoError(false)
	f.idp.SetRefreshBehaviour(fakeidp.RefreshRotate)
	f.clock.Advance(5 * time.Minute)

	res := f.refresh(t, a)
	assert.Equal(t, http.StatusOK, res.status, "%v", res.body)
}

// Of two concurrent refreshes, the response that completes last must carry
// the current refresh token: that is the one an app naturally keeps.
func TestToken_RefreshConcurrentLastResponseStaysCurrent(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	rt := f.fullLogin(t)
	f.idp.SetRefreshDelay(200 * time.Millisecond)

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		last tokenResult
	)

	for range 2 {
		wg.Go(func() {
			res := f.refresh(t, rt)

			mu.Lock()
			defer mu.Unlock()

			require.Equal(t, http.StatusOK, res.status, "%v", res.body)
			last = res
		})
		time.Sleep(50 * time.Millisecond) // one reaches the IdP first
	}

	wg.Wait()

	f.idp.SetRefreshDelay(0)
	f.clock.Advance(11 * time.Second) // grace window closed

	res := f.refresh(t, last.str("refresh_token"))
	assert.Equal(t, http.StatusOK, res.status, "%v", res.body)
}
