package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// transitData is the payload stored in the signed transit cookie.
// Short-lived; carries no long-term identity information.
type transitData struct {
	State        string `json:"s"`
	Nonce        string `json:"n"`
	CodeVerifier string `json:"v"`
	Target       string `json:"t,omitempty"`
	IssuedAt     int64  `json:"iat"`
}

// transitCodec wraps an HMAC signing key (and optional deprecated keys
// for rotation) for the transit cookie.
type transitCodec struct {
	name           string
	ttl            time.Duration
	path           string
	signingKey     []byte
	deprecatedKeys [][]byte
	secure         bool
	nowFunc        func() time.Time
}

func (c *transitCodec) now() time.Time {
	if c.nowFunc != nil {
		return c.nowFunc()
	}

	return time.Now()
}

// write encodes and signs the transit data and writes it as a cookie.
func (c *transitCodec) write(w http.ResponseWriter, d transitData) error {
	d.IssuedAt = c.now().Unix()

	body, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("marshal transit: %w", err)
	}

	payload := base64.RawURLEncoding.EncodeToString(body)
	sig := sign(c.signingKey, payload)
	value := payload + "." + sig
	http.SetCookie(w, &http.Cookie{
		Name:     c.name,
		Value:    value,
		Path:     c.path,
		MaxAge:   int(c.ttl.Seconds()),
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	})

	return nil
}

// read validates the cookie and returns the decoded transit data. A
// missing, expired, malformed or tampered cookie returns a non-nil
// error. The caller is expected to delete the cookie afterwards via
// `delete`.
func (c *transitCodec) read(r *http.Request) (transitData, error) {
	var zero transitData

	cookie, err := r.Cookie(c.name)
	if err != nil {
		return zero, fmt.Errorf("missing transit cookie: %w", err)
	}

	parts := strings.SplitN(cookie.Value, ".", 2)
	if len(parts) != 2 {
		return zero, errors.New("malformed transit cookie")
	}

	payload, sig := parts[0], parts[1]
	if !c.verify(payload, sig) {
		return zero, errors.New("invalid transit signature")
	}

	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return zero, fmt.Errorf("decode transit payload: %w", err)
	}

	var d transitData
	if err := json.Unmarshal(body, &d); err != nil {
		return zero, fmt.Errorf("unmarshal transit: %w", err)
	}

	if c.now().After(time.Unix(d.IssuedAt, 0).Add(c.ttl)) {
		return zero, errors.New("transit cookie expired")
	}

	return d, nil
}

// verify accepts signatures from the primary key or any configured
// deprecated key (key rotation).
func (c *transitCodec) verify(payload, sig string) bool {
	if verifySig(c.signingKey, payload, sig) {
		return true
	}

	for _, k := range c.deprecatedKeys {
		if verifySig(k, payload, sig) {
			return true
		}
	}

	return false
}

// delete clears the transit cookie from the browser.
func (c *transitCodec) delete(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.name,
		Value:    "",
		Path:     c.path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func sign(key []byte, payload string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))

	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifySig(key []byte, payload, sig string) bool {
	expected := sign(key, payload)
	return hmac.Equal([]byte(expected), []byte(sig))
}
