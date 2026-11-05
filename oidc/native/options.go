package native

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/foomo/go/options"

	sso "github.com/foomo/gosso"
)

// Option configures a Broker.
type Option = options.OptionE[*Broker]

const (
	defaultCodeTTL       = 60 * time.Second
	defaultSessionTTL    = 90 * 24 * time.Hour
	defaultRotationGrace = 10 * time.Second
)

// defaultLoginScopes are requested on native logins unless
// WithLoginScopes replaces them.
var defaultLoginScopes = []string{"offline_access"}

// WithCodeTTL sets how long a one-time code can be redeemed. Default 60s.
func WithCodeTTL(d time.Duration) Option {
	return func(b *Broker) error {
		if d <= 0 {
			return errors.New("code ttl must be > 0")
		}

		b.codeTTL = d

		return nil
	}
}

// WithSessionTTL sets the absolute lifetime of a refresh session, counted
// from login. Default 90 days.
func WithSessionTTL(d time.Duration) Option {
	return func(b *Broker) error {
		if d <= 0 {
			return errors.New("session ttl must be > 0")
		}

		b.sessionTTL = d

		return nil
	}
}

// WithRotationGrace sets how long the previous refresh tokens keep working
// after a rotation is stored, so concurrent or retried refreshes from one
// app all succeed. Default 10s.
//
// 0 disables the grace window: rotation is strict, and a second refresh
// with the same token counts as reuse and ends the session, even one sent
// concurrently with the first. Use it only when the app serialises its
// refreshes and never retries one whose response it lost.
func WithRotationGrace(d time.Duration) Option {
	return func(b *Broker) error {
		if d < 0 {
			return errors.New("rotation grace must be >= 0")
		}

		b.rotationGrace = d

		return nil
	}
}

// WithDeprecatedEncryptionKeys adds previous encryption keys that still
// open stored IdP refresh tokens, for key rotation. Each must be exactly
// 32 bytes; empty entries are skipped.
func WithDeprecatedEncryptionKeys(keys ...[]byte) Option {
	return func(b *Broker) error {
		for _, k := range keys {
			if len(k) == 0 {
				continue
			}

			if len(k) != encryptionKeyBytes {
				return fmt.Errorf("deprecated encryption key must be exactly %d bytes, got %d", encryptionKeyBytes, len(k))
			}

			b.deprecatedKeys = append(b.deprecatedKeys, append([]byte(nil), k...))
		}

		return nil
	}
}

// WithLoginScopes replaces the scopes a native login requests on top of
// the RP's own. Default offline_access, which most IdPs need to issue the
// refresh token the broker requires; web logins through the same RP do
// not request it, so they open no offline session at the IdP. Without
// arguments a native login requests the RP's scopes only.
func WithLoginScopes(scopes ...string) Option {
	return func(b *Broker) error {
		b.loginScopes = slices.Clone(scopes)
		return nil
	}
}

// WithErrorLogger routes runtime errors to fn. Responses stay generic.
func WithErrorLogger(fn sso.ErrorLogger) Option {
	return func(b *Broker) error {
		b.errorLogger = fn
		return nil
	}
}

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option {
	return func(b *Broker) error {
		if now == nil {
			return errors.New("clock must not be nil")
		}

		b.now = now

		return nil
	}
}
