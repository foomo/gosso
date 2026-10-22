package store

// EncryptedToken is an AES-256-GCM ciphertext (nonce prefixed) and the ID
// of the key that sealed it.
type EncryptedToken struct {
	KeyID      string
	Ciphertext []byte
}
