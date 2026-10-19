package native

import (
	"net/http"
	"net/url"
	"testing"

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

		_, err := f.store.GetSession(t.Context(), id)
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("previous token within grace", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		rt, id := issue(t, f)

		s, err := f.store.GetSession(t.Context(), id)
		require.NoError(t, err)

		next := s
		next.PreviousRefreshHash = s.RefreshHash
		next.RefreshHash = "rotated"
		next.RotatedAt = f.clock.Now()
		require.NoError(t, f.store.RotateSession(t.Context(), next, s.RefreshHash))

		assert.Equal(t, http.StatusOK, revoke(t, f, url.Values{"token": {rt}, "client_id": {clientIOS}}).status)

		_, err = f.store.GetSession(t.Context(), id)
		require.ErrorIs(t, err, ErrNotFound)
	})

	keeps := map[string]func(rt, id string) url.Values{
		"wrong secret": func(_, id string) url.Values {
			return url.Values{"token": {id + ".wrong"}, "client_id": {clientIOS}}
		},
		"other client": func(rt, _ string) url.Values {
			return url.Values{"token": {rt}, "client_id": {clientAndroid}}
		},
		"no client": func(rt, _ string) url.Values {
			return url.Values{"token": {rt}}
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

			_, err := f.store.GetSession(t.Context(), id)
			require.NoError(t, err, "session kept")
		})
	}

	t.Run("missing token", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)
		assertOAuthError(t, revoke(t, f, url.Values{"client_id": {clientIOS}}), http.StatusBadRequest, errInvalidRequest)
	})
}
