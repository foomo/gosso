package oidc

import (
	"strings"
	"testing"

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

func TestWithIssuerURL_RequiresHTTPS(t *testing.T) {
	t.Parallel()

	_, err := apply(t, WithIssuerURL("http://login.example.com/"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestWithIssuerURL_LoopbackHTTPAllowed(t *testing.T) {
	t.Parallel()

	for _, host := range []string{
		"http://localhost:8080/realms/x",
		"http://127.0.0.1:8080/realms/x",
		"http://[::1]:8080/realms/x",
	} {
		rp, err := apply(t, WithIssuerURL(host))
		require.NoError(t, err, host)
		assert.Equal(t, host, rp.issuerURL)
	}
}

func TestWithIssuerURL_HTTPSAccepted(t *testing.T) {
	t.Parallel()

	rp, err := apply(t, WithIssuerURL("https://login.example.com/"))
	require.NoError(t, err)
	assert.Equal(t, "https://login.example.com/", rp.issuerURL)
}

func TestWithIssuerURL_Empty(t *testing.T) {
	t.Parallel()

	_, err := apply(t, WithIssuerURL(""))
	require.Error(t, err)
}

func TestWithRedirectURL_RequiresHTTPS(t *testing.T) {
	t.Parallel()

	_, err := apply(t, WithRedirectURL("http://app.example.com/cb"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestWithRedirectURL_LoopbackHTTPAllowed(t *testing.T) {
	t.Parallel()

	_, err := apply(t, WithRedirectURL("http://localhost:8080/cb"))
	require.NoError(t, err)
}

func TestWithTransitSigningKey_MinLength(t *testing.T) {
	t.Parallel()

	_, err := apply(t, WithTransitSigningKey([]byte("too-short")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")

	long := []byte(strings.Repeat("k", 32))
	rp, err := apply(t, WithTransitSigningKey(long))
	require.NoError(t, err)
	assert.Equal(t, long, rp.transitSigningKey)
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
