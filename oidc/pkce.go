package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// generateVerifier returns a cryptographically random PKCE code_verifier
// per RFC 7636 §4.1 (43 characters base64url without padding, derived
// from 32 bytes of entropy).
func generateVerifier() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("random verifier: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// codeChallenge returns base64url(SHA256(verifier)) as required by
// RFC 7636 §4.2 for the S256 method.
func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// generateNonce returns a base64url nonce derived from 32 bytes.
func generateNonce() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("random nonce: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// generateState returns a base64url state value derived from 32 bytes.
func generateState() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("random state: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}
