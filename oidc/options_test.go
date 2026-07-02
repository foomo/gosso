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
