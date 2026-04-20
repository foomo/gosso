package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodeChallenge_RFC7636Vector(t *testing.T) {
	t.Parallel()
	// RFC 7636 appendix B test vector.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	expected := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	assert.Equal(t, expected, codeChallenge(verifier))
}

func TestCodeChallenge_IsSHA256(t *testing.T) {
	t.Parallel()

	verifier := "some-verifier-value"
	sum := sha256.Sum256([]byte(verifier))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), codeChallenge(verifier))
}

func TestGenerateVerifier_Length(t *testing.T) {
	t.Parallel()

	v, err := generateVerifier()
	require.NoError(t, err)
	// 32 bytes -> 43 base64url chars without padding.
	assert.Len(t, v, 43)
}

func TestGenerateVerifier_Uniqueness(t *testing.T) {
	t.Parallel()

	v1, err := generateVerifier()
	require.NoError(t, err)
	v2, err := generateVerifier()
	require.NoError(t, err)
	assert.NotEqual(t, v1, v2)
}
