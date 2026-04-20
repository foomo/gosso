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
