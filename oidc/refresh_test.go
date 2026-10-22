package oidc

import (
	"net/http"
	"testing"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/internal/fakeidp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loginRefreshToken runs a web login against the fixture's fake IdP and
// returns the IdP refresh token it issued.
func loginRefreshToken(t *testing.T, f *rpFixture) string {
	t.Helper()

	resp := f.get(t, "/login")
	require.Equal(t, http.StatusFound, resp.StatusCode)

	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()

	require.NotEmpty(t, f.rec.refreshToken)

	return f.rec.refreshToken
}

func TestRefresh(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		behaviour fakeidp.RefreshBehaviour
		userInfo  bool
		check     func(t *testing.T, input string, r refreshResult)
	}{
		"rotated": {
			behaviour: fakeidp.RefreshRotate,
			check: func(t *testing.T, input string, r refreshResult) {
				t.Helper()
				require.NoError(t, r.err)
				assert.Equal(t, "alice", r.sub.ExternalID)
				assert.Equal(t, "alice@example.com", r.sub.Email)
				assert.NotEmpty(t, r.sub.Raw.RefreshToken)
				assert.NotEqual(t, input, r.sub.Raw.RefreshToken)
				assert.NotEmpty(t, r.sub.Raw.RawIDToken)
				assert.NotEmpty(t, r.sub.Raw.AccessToken)
			},
		},
		"rotated with userinfo": {
			behaviour: fakeidp.RefreshRotate,
			userInfo:  true,
			check: func(t *testing.T, _ string, r refreshResult) {
				t.Helper()
				require.NoError(t, r.err)
				assert.Equal(t, "alice", r.sub.ExternalID)
				assert.NotNil(t, r.sub.Raw.UserInfo)
			},
		},
		"unchanged": {
			behaviour: fakeidp.RefreshKeep,
			check: func(t *testing.T, input string, r refreshResult) {
				t.Helper()
				require.NoError(t, r.err)
				assert.Equal(t, input, r.sub.Raw.RefreshToken)
			},
		},
		"no id token": {
			behaviour: fakeidp.RefreshNoIDToken,
			check: func(t *testing.T, _ string, r refreshResult) {
				t.Helper()
				require.NoError(t, r.err)
				assert.Equal(t, "alice", r.sub.ExternalID)
				assert.Equal(t, "alice@example.com", r.sub.Email)
				assert.Empty(t, r.sub.Raw.RawIDToken)
				assert.Nil(t, r.sub.Raw.IDToken)
				assert.NotNil(t, r.sub.Raw.UserInfo)
			},
		},
		"rejected": {
			behaviour: fakeidp.RefreshReject,
			check: func(t *testing.T, _ string, r refreshResult) {
				t.Helper()
				require.ErrorIs(t, r.err, ErrRefreshRejected)
			},
		},
		"server error": {
			behaviour: fakeidp.RefreshServerError,
			check: func(t *testing.T, _ string, r refreshResult) {
				t.Helper()
				require.Error(t, r.err)
				assert.NotErrorIs(t, r.err, ErrRefreshRejected)
			},
		},
		"subject mismatch": {
			behaviour: fakeidp.RefreshOtherSubject,
			check: func(t *testing.T, _ string, r refreshResult) {
				t.Helper()
				require.Error(t, r.err)
				assert.NotErrorIs(t, r.err, ErrRefreshRejected)
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newRPFixture(t, nil)
			f.rp.fetchUserInfo = tc.userInfo
			input := loginRefreshToken(t, f)

			f.idp.SetRefreshBehaviour(tc.behaviour)

			sub, err := f.rp.Refresh(t.Context(), input, "alice")
			tc.check(t, input, refreshResult{sub: sub, err: err})
			assert.Equal(t, 1, f.idp.RefreshCalls())
		})
	}
}

func TestRefresh_FailureAfterGrantKeepsNewToken(t *testing.T) {
	t.Parallel()

	f := newRPFixture(t, nil)
	input := loginRefreshToken(t, f)

	// the grant succeeds and rotates, then UserInfo (needed: no ID token) fails
	f.idp.SetRefreshBehaviour(fakeidp.RefreshNoIDToken)
	f.idp.SetUserInfoError(true)

	_, err := f.rp.Refresh(t.Context(), input, "alice")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrRefreshRejected)

	var rfe *RefreshFailedError
	require.ErrorAs(t, err, &rfe)
	require.NotEmpty(t, rfe.RefreshToken)
	assert.NotEqual(t, input, rfe.RefreshToken, "the IdP rotated; the retired input is useless")

	// the token handed back is the one that works now
	f.idp.SetUserInfoError(false)
	f.idp.SetRefreshBehaviour(fakeidp.RefreshRotate)

	_, err = f.rp.Refresh(t.Context(), rfe.RefreshToken, "alice")
	require.NoError(t, err)
}

func TestRefresh_GrantFailureIsNotRefreshFailedError(t *testing.T) {
	t.Parallel()

	f := newRPFixture(t, nil)
	input := loginRefreshToken(t, f)
	f.idp.SetRefreshBehaviour(fakeidp.RefreshServerError)

	_, err := f.rp.Refresh(t.Context(), input, "alice")

	var rfe *RefreshFailedError
	assert.NotErrorAs(t, err, &rfe, "no new token when the grant itself failed")
}

func TestRefresh_EmptyToken(t *testing.T) {
	t.Parallel()

	f := newRPFixture(t, nil)

	_, err := f.rp.Refresh(t.Context(), "", "alice")
	require.ErrorIs(t, err, ErrRefreshRejected)
	assert.Zero(t, f.idp.RefreshCalls())
}

type refreshResult struct {
	sub sso.Subject[Payload]
	err error
}
