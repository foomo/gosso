// Package tokens generates random tokens and their S256 hashes, shared by
// the OIDC adapter (state, nonce, PKCE) and the native broker (codes,
// refresh secrets, session IDs).
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// Random returns base64url(n random bytes) without padding.
func Random(n int) string {
	b := make([]byte, n)
	// never fails: crypto/rand.Read crashes the program rather than
	// return an error (Go 1.24+)
	_, _ = rand.Read(b)

	return base64.RawURLEncoding.EncodeToString(b)
}

// S256 returns base64url(SHA-256(v)) without padding: the PKCE S256
// code_challenge of a verifier (RFC 7636 §4.2), and the at-rest form of
// codes and refresh secrets.
func S256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
