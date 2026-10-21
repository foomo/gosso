package native

import (
	"errors"
	"fmt"
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
// app all succeed. Default 10s; 0 disables the grace window.
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
