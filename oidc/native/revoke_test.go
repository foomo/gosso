package native

import (
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/foomo/gosso/oidc/native/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRevoke(t *testing.T) {
	t.Parallel()

	issue := func(t *testing.T, f *fixture) (string, string) {
		t.Helper()

		res := f.post(t, "/app/token", codeForm(f.seedCode(t)))
		require.Equal(t, http.StatusOK, res.status)

		rt := res.str("refresh_token")
		id, _, _ := cutToken(rt)

		return rt, id
	}

	revoke := func(t *testing.T, f *fixture, form url.Values) tokenResult {
		t.Helper()

		res := f.post(t, "/app/revoke", form)
		assert.Equal(t, "no-store", res.header.Get("Cache-Control"))

		return res
	}

	t.Run("valid token deletes the session", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		rt, id := issue(t, f)

		res := revoke(t, f, url.Values{"token": {rt}, "client_id": {clientIOS}})
		assert.Equal(t, http.StatusOK, res.status)
		assert.Empty(t, res.body)

		_, err := f.sessions.Get(t.Context(), id)
		require.ErrorIs(t, err, repository.ErrNotFound)
	})

	t.Run("previous token within grace", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		rt, id := issue(t, f)

		s, err := f.sessions.Get(t.Context(), id)
		require.NoError(t, err)

		next := s
		retire(&next, "rotated", f.clock.Now())
		require.NoError(t, f.sessions.Rotate(t.Context(), next))

		assert.Equal(t, http.StatusOK, revoke(t, f, url.Values{"token": {rt}, "client_id": {clientIOS}}).status)

		_, err = f.sessions.Get(t.Context(), id)
		require.ErrorIs(t, err, repository.ErrNotFound)
	})

	// a rotated token ends the session at the token endpoint (reuse), so
	// it must end it here too: otherwise a thief who refreshed first keeps
	// the session through the user's sign-out
	for name, rotations := range map[string]int{
		"previous token after grace": 1,
		"retired token":              2,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			rt, id := issue(t, f)

			for i := range rotations {
				s, err := f.sessions.Get(t.Context(), id)
				require.NoError(t, err)

				next := s
				retire(&next, "rotated-"+strconv.Itoa(i), f.clock.Now())
				require.NoError(t, f.sessions.Rotate(t.Context(), next))
			}

			f.clock.Advance(11 * time.Second) // grace window closed

			assert.Equal(t, http.StatusOK, revoke(t, f, url.Values{"token": {rt}, "client_id": {clientIOS}}).status)

			_, err := f.sessions.Get(t.Context(), id)
			require.ErrorIs(t, err, repository.ErrNotFound)
		})
	}

	keeps := map[string]func(rt, id string) url.Values{
		"wrong secret": func(_, id string) url.Values {
			return url.Values{"token": {id + ".wrong"}, "client_id": {clientIOS}}
		},
		"other client": func(rt, _ string) url.Values {
			return url.Values{"token": {rt}, "client_id": {clientAndroid}}
		},
		"garbage": func(string, string) url.Values {
			return url.Values{"token": {"garbage"}, "client_id": {clientIOS}}
		},
	}

	for name, form := range keeps {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			rt, id := issue(t, f)

			res := revoke(t, f, form(rt, id))
			assert.Equal(t, http.StatusOK, res.status)

			_, err := f.sessions.Get(t.Context(), id)
			require.NoError(t, err, "session kept")
		})
	}

	for name, form := range map[string]func(rt string) url.Values{
		"no client":      func(rt string) url.Values { return url.Values{"token": {rt}} },
		"unknown client": func(rt string) url.Values { return url.Values{"token": {rt}, "client_id": {"nope"}} },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			rt, id := issue(t, f)

			// RFC 7009 §2.1: the client must identify itself
			assertOAuthError(t, revoke(t, f, form(rt)), http.StatusBadRequest, errInvalidClient)

			_, err := f.sessions.Get(t.Context(), id)
			require.NoError(t, err, "session kept")
		})
	}

	for name, broken := range map[string]brokenSessions{
		"get fails":    {failGet: true},
		"delete fails": {failDelete: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newFixtureWithSessions(t, func(s repository.Session) repository.Session {
				broken.Session = s
				return broken
			})
			rt, id := issue(t, f)

			// RFC 7009 §2.2.1: not revoked, so the app must not drop its token
			assertOAuthError(t, revoke(t, f, url.Values{"token": {rt}, "client_id": {clientIOS}}), http.StatusServiceUnavailable, errTemporarilyUnavailable)

			_, err := f.sessions.Get(t.Context(), id)
			require.NoError(t, err, "session kept")
		})
	}

	t.Run("missing token", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		assertOAuthError(t, revoke(t, f, url.Values{"client_id": {clientIOS}}), http.StatusBadRequest, errInvalidRequest)
	})
}
