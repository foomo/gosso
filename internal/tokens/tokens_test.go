package tokens_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/foomo/gosso/internal/tokens"
)

func TestRandom(t *testing.T) {
	t.Parallel()

	a := tokens.Random(32)
	assert.Len(t, a, 43, "32 bytes are 43 base64url characters")
	assert.NotEqual(t, a, tokens.Random(32))
	assert.Len(t, tokens.Random(16), 22)
}

func TestS256(t *testing.T) {
	t.Parallel()

	// RFC 7636 appendix B
	assert.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", tokens.S256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
	// base64url(sha256("abc"))
	assert.Equal(t, "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", tokens.S256("abc"))
}
