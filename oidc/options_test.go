package oidc

import (
	"context"
	"net/http"
	"strings"
	"testing"

	sso "github.com/foomo/gosso"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func apply(t *testing.T, opts ...Option) (*RP, error) {
	t.Helper()

	rp := &RP{}
	for _, o := range opts {
		if err := o(rp); err != nil {
			return nil, err
		}
	}

	return rp, nil
}

func TestWithOnRedirect(t *testing.T) {
	t.Parallel()

	rp, err := apply(t)
	require.NoError(t, err)
	assert.Nil(t, rp.onRedirect, "unset by default")

	rp, err = apply(t, WithOnRedirect(func(_ context.Context, _ http.ResponseWriter, _ *http.Request, _ sso.Subject[Payload], target string) (string, error) {
		return target + "?merged=1", nil
	}))
	require.NoError(t, err)
	require.NotNil(t, rp.onRedirect)

	got, err := rp.onRedirect(context.Background(), nil, nil, sso.Subject[Payload]{}, "/account")
	require.NoError(t, err)
	assert.Equal(t, "/account?merged=1", got)
}

func TestWithTransitDeprecatedKeys_MinLength(t *testing.T) {
	t.Parallel()

	_, err := apply(t, WithTransitDeprecatedKeys([]byte("too-short")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")

	long := []byte(strings.Repeat("k", 32))
	rp, err := apply(t, WithTransitDeprecatedKeys(long))
	require.NoError(t, err)
	require.Len(t, rp.transitDeprecatedKeys, 1)
	assert.Equal(t, long, rp.transitDeprecatedKeys[0])

	// Empty slices are silently dropped (they represent "no-op"
	// rotation entries) rather than rejected.
	rp, err = apply(t, WithTransitDeprecatedKeys(nil, []byte{}))
	require.NoError(t, err)
	assert.Empty(t, rp.transitDeprecatedKeys)
}

func TestWithBootstrapTimeout_Positive(t *testing.T) {
	t.Parallel()

	_, err := apply(t, WithBootstrapTimeout(0))
	require.Error(t, err)

	_, err = apply(t, WithBootstrapTimeout(-1))
	require.Error(t, err)
}

func TestWithScopes(t *testing.T) {
	t.Parallel()

	t.Run("default set", func(t *testing.T) {
		t.Parallel()

		rp, err := apply(t, WithExtraScopes("offline_access"))
		require.NoError(t, err)
		assert.Equal(t, []string{"openid", "profile", "email", "offline_access"}, rp.scopes())
	})

	t.Run("replaced set keeps openid and the extra scopes", func(t *testing.T) {
		t.Parallel()

		// e.g. an IdP that rejects the whole request over `email`
		rp, err := apply(t, WithScopes("profile"), WithExtraScopes("offline_access"))
		require.NoError(t, err)
		assert.Equal(t, []string{"openid", "profile", "offline_access"}, rp.scopes())
	})

	t.Run("openid listed explicitly is not duplicated", func(t *testing.T) {
		t.Parallel()

		rp, err := apply(t, WithScopes("openid", "profile"))
		require.NoError(t, err)
		assert.Equal(t, []string{"openid", "profile"}, rp.scopes())
	})

	t.Run("an empty replacement still requests openid", func(t *testing.T) {
		t.Parallel()

		rp, err := apply(t, WithScopes())
		require.NoError(t, err)
		assert.Equal(t, []string{"openid"}, rp.scopes())
	})

	t.Run("the default set is not aliased", func(t *testing.T) {
		t.Parallel()

		first, err := apply(t, WithExtraScopes("a"))
		require.NoError(t, err)
		second, err := apply(t, WithExtraScopes("b"))
		require.NoError(t, err)

		assert.Equal(t, []string{"openid", "profile", "email", "a"}, first.scopes())
		assert.Equal(t, []string{"openid", "profile", "email", "b"}, second.scopes())
	})
}

func TestUnsupportedScopes(t *testing.T) {
	t.Parallel()

	requested := []string{"openid", "profile", "email", "offline_access"}

	assert.Equal(t, []string{"email"},
		unsupportedScopes(requested, []string{"openid", "profile", "address", "offline_access"}))
	assert.Nil(t, unsupportedScopes(requested, []string{"openid", "profile", "email", "offline_access"}))
	assert.Nil(t, unsupportedScopes(requested, nil), "no scopes_supported, nothing to check")
}
