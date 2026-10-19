// Package nativetest holds the contract suite every native.Store
// implementation must pass.
package nativetest

import (
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/foomo/gosso/oidc/native"
)

const attrCustomer = "customer"

// TestStore runs the native.Store contract against stores built by
// newStore; each subtest gets a fresh store. Times are truncated to
// milliseconds, the precision MongoDB keeps.
func TestStore(t *testing.T, newStore func(t *testing.T) native.Store) {
	t.Helper()

	now := time.Now().UTC().Truncate(time.Millisecond)

	code := func(hash string) native.Code {
		return native.Code{
			Hash:          hash,
			ClientID:      "app-ios",
			RedirectURI:   "com.example.app:/oauth2redirect",
			CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			Subject: native.Subject{
				ExternalID: "alice",
				Email:      "alice@example.com",
				Firstname:  "Alice",
				Lastname:   "Example",
				Groups:     []string{"admins", "users"},
			},
			Attributes:      native.Attributes{attrCustomer: "c-1"},
			IDPRefreshToken: native.EncryptedToken{KeyID: "k1", Ciphertext: []byte{1, 2, 3}},
			ExpiresAt:       now.Add(time.Minute),
		}
	}

	session := func(id string) native.Session {
		return native.Session{
			ID:                  id,
			ClientID:            "app-ios",
			RefreshHash:         "h1",
			PreviousRefreshHash: "h0",
			RotatedAt:           now.Add(-time.Second),
			Subject: native.Subject{
				ExternalID: "alice",
				Email:      "alice@example.com",
				Firstname:  "Alice",
				Lastname:   "Example",
				Groups:     []string{"admins"},
			},
			Attributes:      native.Attributes{attrCustomer: "c-1"},
			IDPRefreshToken: native.EncryptedToken{KeyID: "k1", Ciphertext: []byte{4, 5, 6}},
			CreatedAt:       now.Add(-time.Hour),
			LastUsedAt:      now,
			ExpiresAt:       now.Add(24 * time.Hour),
		}
	}

	t.Run("code round trip", func(t *testing.T) {
		s := newStore(t)
		in := code("c1")
		require.NoError(t, s.PutCode(t.Context(), in))

		out, err := s.TakeCode(t.Context(), "c1")
		require.NoError(t, err)
		assertEqualCode(t, in, out)
	})

	t.Run("take twice", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.PutCode(t.Context(), code("c1")))

		_, err := s.TakeCode(t.Context(), "c1")
		require.NoError(t, err)

		_, err = s.TakeCode(t.Context(), "c1")
		require.ErrorIs(t, err, native.ErrNotFound)
	})

	t.Run("take unknown", func(t *testing.T) {
		s := newStore(t)

		_, err := s.TakeCode(t.Context(), "nope")
		require.ErrorIs(t, err, native.ErrNotFound)
	})

	t.Run("concurrent take", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.PutCode(t.Context(), code("c1")))

		var (
			wg       sync.WaitGroup
			won      atomic.Int32
			notFound atomic.Int32
		)

		for range 16 {
			wg.Go(func() {
				_, err := s.TakeCode(t.Context(), "c1")

				switch {
				case err == nil:
					won.Add(1)
				case errors.Is(err, native.ErrNotFound):
					notFound.Add(1)
				}
			})
		}

		wg.Wait()
		assert.Equal(t, int32(1), won.Load())
		assert.Equal(t, int32(15), notFound.Load())
	})

	t.Run("session round trip", func(t *testing.T) {
		s := newStore(t)
		in := session("s1")
		require.NoError(t, s.CreateSession(t.Context(), in))

		out, err := s.GetSession(t.Context(), "s1")
		require.NoError(t, err)
		assertEqualSession(t, in, out)
	})

	t.Run("session empty groups normalised to nil", func(t *testing.T) {
		s := newStore(t)
		in := session("s1")
		in.Subject.Groups = []string{}
		require.NoError(t, s.CreateSession(t.Context(), in))

		out, err := s.GetSession(t.Context(), "s1")
		require.NoError(t, err)
		assert.Nil(t, out.Subject.Groups)

		in.Subject.Groups = nil
		in.ID = "s2"

		require.NoError(t, s.CreateSession(t.Context(), in))

		out, err = s.GetSession(t.Context(), "s2")
		require.NoError(t, err)
		assert.Nil(t, out.Subject.Groups)
	})

	t.Run("get missing", func(t *testing.T) {
		s := newStore(t)

		_, err := s.GetSession(t.Context(), "nope")
		require.ErrorIs(t, err, native.ErrNotFound)
	})

	t.Run("rotate with current hash", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.CreateSession(t.Context(), session("s1")))

		next := session("s1")
		next.RefreshHash = "h2"
		next.PreviousRefreshHash = "h1"
		next.RotatedAt = now
		next.Attributes = native.Attributes{attrCustomer: "c-2"}
		require.NoError(t, s.RotateSession(t.Context(), next, "h1"))

		out, err := s.GetSession(t.Context(), "s1")
		require.NoError(t, err)
		assertEqualSession(t, next, out)
	})

	t.Run("rotate with stale hash", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.CreateSession(t.Context(), session("s1")))

		next := session("s1")
		next.RefreshHash = "h2"
		require.ErrorIs(t, s.RotateSession(t.Context(), next, "h0"), native.ErrConflict)

		out, err := s.GetSession(t.Context(), "s1")
		require.NoError(t, err)
		assert.Equal(t, "h1", out.RefreshHash)
	})

	t.Run("concurrent rotate", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.CreateSession(t.Context(), session("s1")))

		var (
			wg       sync.WaitGroup
			won      atomic.Int32
			conflict atomic.Int32
		)

		for i := range 16 {
			wg.Go(func() {
				next := session("s1")
				next.RefreshHash = "h2-" + strconv.Itoa(i)

				err := s.RotateSession(t.Context(), next, "h1")

				switch {
				case err == nil:
					won.Add(1)
				case errors.Is(err, native.ErrConflict):
					conflict.Add(1)
				}
			})
		}

		wg.Wait()
		assert.Equal(t, int32(1), won.Load())
		assert.Equal(t, int32(15), conflict.Load())
	})

	t.Run("rotate missing session", func(t *testing.T) {
		s := newStore(t)
		require.ErrorIs(t, s.RotateSession(t.Context(), session("nope"), "h1"), native.ErrConflict)
	})

	t.Run("delete twice", func(t *testing.T) {
		s := newStore(t)
		require.NoError(t, s.CreateSession(t.Context(), session("s1")))
		require.NoError(t, s.DeleteSession(t.Context(), "s1"))
		require.NoError(t, s.DeleteSession(t.Context(), "s1"))

		_, err := s.GetSession(t.Context(), "s1")
		require.ErrorIs(t, err, native.ErrNotFound)
	})

	t.Run("stored values are copies", func(t *testing.T) {
		s := newStore(t)
		in := session("s1")
		require.NoError(t, s.CreateSession(t.Context(), in))

		in.Attributes[attrCustomer] = "mutated"
		in.Subject.Groups[0] = "mutated"

		out, err := s.GetSession(t.Context(), "s1")
		require.NoError(t, err)
		assert.Equal(t, "c-1", out.Attributes[attrCustomer])
		assert.Equal(t, "admins", out.Subject.Groups[0])
	})
}

func assertEqualCode(t *testing.T, want, got native.Code) {
	t.Helper()

	assert.True(t, want.ExpiresAt.Equal(got.ExpiresAt), "ExpiresAt %v != %v", want.ExpiresAt, got.ExpiresAt)
	want.ExpiresAt, got.ExpiresAt = time.Time{}, time.Time{}
	assert.Equal(t, want, got)
}

func assertEqualSession(t *testing.T, want, got native.Session) {
	t.Helper()

	for _, p := range []struct{ w, g *time.Time }{
		{&want.RotatedAt, &got.RotatedAt},
		{&want.CreatedAt, &got.CreatedAt},
		{&want.LastUsedAt, &got.LastUsedAt},
		{&want.ExpiresAt, &got.ExpiresAt},
	} {
		assert.True(t, p.w.Equal(*p.g), "time %v != %v", *p.w, *p.g)
		*p.w, *p.g = time.Time{}, time.Time{}
	}

	assert.Equal(t, want, got)
}
