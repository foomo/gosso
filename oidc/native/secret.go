package native

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// encryptionKeyBytes is the AES-256 key length.
const encryptionKeyBytes = 32

// randomToken returns base64url(n random bytes) without padding.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken returns base64url(SHA-256(v)), the at-rest form of codes and
// refresh secrets.
func hashToken(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyS256 reports whether challenge is base64url(SHA-256(verifier)).
// A malformed verifier never matches.
func verifyS256(verifier, challenge string) bool {
	if !validVerifier(verifier) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(hashToken(verifier)), []byte(challenge)) == 1
}

// validVerifier checks RFC 7636 §4.1: 43–128 characters of
// [A-Za-z0-9-._~].
func validVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}

	for _, c := range []byte(v) {
		if !isUnreserved(c) {
			return false
		}
	}

	return true
}

// validChallenge checks an S256 challenge: exactly 43 base64url characters.
func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}

	for _, b := range []byte(c) {
		if !isAlnum(b) && b != '-' && b != '_' {
			return false
		}
	}

	return true
}

func isAlnum(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func isUnreserved(c byte) bool {
	return isAlnum(c) || c == '-' || c == '.' || c == '_' || c == '~'
}

// sealer encrypts IdP refresh tokens with AES-256-GCM. It seals with the
// primary key and opens with any known key, looked up by KeyID.
type sealer struct {
	primaryID string
	keys      map[string]cipher.AEAD
}

func newSealer(primary []byte, deprecated ...[]byte) (*sealer, error) {
	s := &sealer{keys: map[string]cipher.AEAD{}}

	for i, key := range append([][]byte{primary}, deprecated...) {
		if len(key) != encryptionKeyBytes {
			return nil, fmt.Errorf("encryption key must be exactly %d bytes, got %d", encryptionKeyBytes, len(key))
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aes: %w", err)
		}

		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("gcm: %w", err)
		}

		id := keyID(key)
		if i == 0 {
			s.primaryID = id
		}

		s.keys[id] = aead
	}

	return s, nil
}

// keyID is hex(SHA-256(key))[:16].
func keyID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])[:16]
}

// seal encrypts plaintext bound to aad. The random nonce prefixes the
// ciphertext.
func (s *sealer) seal(plaintext, aad string) (EncryptedToken, error) {
	aead := s.keys[s.primaryID]

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedToken{}, fmt.Errorf("random nonce: %w", err)
	}

	return EncryptedToken{
		KeyID:      s.primaryID,
		Ciphertext: aead.Seal(nonce, nonce, []byte(plaintext), []byte(aad)),
	}, nil
}

// open decrypts t, which must have been sealed with the same aad.
func (s *sealer) open(t EncryptedToken, aad string) (string, error) {
	aead, ok := s.keys[t.KeyID]
	if !ok {
		return "", fmt.Errorf("unknown encryption key id %q", t.KeyID)
	}

	if len(t.Ciphertext) < aead.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ct := t.Ciphertext[:aead.NonceSize()], t.Ciphertext[aead.NonceSize():]

	pt, err := aead.Open(nil, nonce, ct, []byte(aad))
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(pt), nil
}

// sealAAD binds a sealed IdP refresh token to its subject, so a stored
// ciphertext cannot be moved to another subject's record.
func sealAAD(externalID string) string {
	return "gosso-native:" + externalID
}
