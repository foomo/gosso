package native

import (
	"strings"
	"testing"

	"github.com/foomo/gosso/oidc/native/repository/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyS256(t *testing.T) {
	t.Parallel()

	// RFC 7636 appendix B
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)

	assert.True(t, verifyS256(verifier, challenge))
	assert.False(t, verifyS256(verifier[:42]+"A", challenge))
	assert.False(t, verifyS256("short", challenge), "malformed verifier")
}

func TestValidVerifier(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		in   string
		want bool
	}{
		"42 chars":      {strings.Repeat("a", 42), false},
		"43 chars":      {strings.Repeat("a", 43), true},
		"128 chars":     {strings.Repeat("a", 128), true},
		"129 chars":     {strings.Repeat("a", 129), false},
		"unreserved":    {strings.Repeat("aZ09-._~", 6), true},
		"illegal plus":  {strings.Repeat("a", 42) + "+", false},
		"illegal space": {strings.Repeat("a", 42) + " ", false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, validVerifier(tc.in))
		})
	}
}

func TestValidChallenge(t *testing.T) {
	t.Parallel()

	assert.True(t, validChallenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))
	assert.False(t, validChallenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c"), "42 chars")
	assert.False(t, validChallenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cMx"), "44 chars")
	assert.False(t, validChallenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM"), "std base64")
	assert.False(t, validChallenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c="), "padded")
}

func TestRandomToken(t *testing.T) {
	t.Parallel()

	a, err := randomToken(32)
	require.NoError(t, err)
	assert.Len(t, a, 43)

	b, err := randomToken(32)
	require.NoError(t, err)
	assert.NotEqual(t, a, b)

	id, err := randomToken(16)
	require.NoError(t, err)
	assert.Len(t, id, 22)
}

func TestHashToken(t *testing.T) {
	t.Parallel()

	// base64url(sha256("abc"))
	assert.Equal(t, "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", hashToken("abc"))
}

func TestSealer(t *testing.T) {
	t.Parallel()

	key1 := []byte(strings.Repeat("1", 32))
	key2 := []byte(strings.Repeat("2", 32))

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()

		s, err := newSealer(key1)
		require.NoError(t, err)

		enc, err := s.seal("idp-rt", "aad")
		require.NoError(t, err)
		assert.NotContains(t, string(enc.Ciphertext), "idp-rt")
		assert.Len(t, enc.KeyID, 16)

		got, err := s.open(enc, "aad")
		require.NoError(t, err)
		assert.Equal(t, "idp-rt", got)
	})

	t.Run("wrong aad", func(t *testing.T) {
		t.Parallel()

		s, err := newSealer(key1)
		require.NoError(t, err)

		enc, err := s.seal("idp-rt", "gosso-native:alice")
		require.NoError(t, err)

		_, err = s.open(enc, "gosso-native:bob")
		require.Error(t, err)
	})

	t.Run("rotation", func(t *testing.T) {
		t.Parallel()

		old, err := newSealer(key1)
		require.NoError(t, err)

		enc, err := old.seal("idp-rt", "aad")
		require.NoError(t, err)

		rotated, err := newSealer(key2, key1)
		require.NoError(t, err)

		got, err := rotated.open(enc, "aad")
		require.NoError(t, err)
		assert.Equal(t, "idp-rt", got)

		fresh, err := rotated.seal("idp-rt", "aad")
		require.NoError(t, err)
		assert.NotEqual(t, enc.KeyID, fresh.KeyID, "new tokens use the primary key")

		withoutOld, err := newSealer(key2)
		require.NoError(t, err)

		_, err = withoutOld.open(enc, "aad")
		require.Error(t, err, "unknown key id")
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		t.Parallel()

		s, err := newSealer(key1)
		require.NoError(t, err)

		enc, err := s.seal("idp-rt", "aad")
		require.NoError(t, err)

		enc.Ciphertext[len(enc.Ciphertext)-1] ^= 1
		_, err = s.open(enc, "aad")
		require.Error(t, err)

		_, err = s.open(store.EncryptedToken{KeyID: enc.KeyID, Ciphertext: []byte{1}}, "aad")
		require.Error(t, err, "shorter than the nonce")
	})

	t.Run("key length", func(t *testing.T) {
		t.Parallel()

		_, err := newSealer([]byte(strings.Repeat("k", 31)))
		require.Error(t, err)

		_, err = newSealer(key1, []byte(strings.Repeat("k", 33)))
		require.Error(t, err)
	})
}
