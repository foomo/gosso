package native

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/foomo/go/options"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/oidc"
	"github.com/foomo/gosso/oidc/native/repository"
)

// Broker serves the native-app endpoints on top of an oidc.RP. Build it
// with New, pass its wrapped hooks to oidc.New, then Attach the RP.
type Broker struct {
	codes          repository.Code
	sessions       repository.Session
	hooks          Hooks
	clients        map[string]Client
	sealer         *sealer
	deprecatedKeys [][]byte
	codeTTL        time.Duration
	sessionTTL     time.Duration
	rotationGrace  time.Duration
	errorLogger    sso.ErrorLogger
	now            func() time.Time

	wrapMu            sync.Mutex
	wrappedAuth       bool
	wrappedRedirect   bool
	wrappedLoginError bool

	rp atomic.Pointer[oidc.RP]
}

// New builds a Broker. codes and sessions persist one-time codes and
// refresh sessions; clients are the registered native apps; encryptionKey
// (exactly 32 bytes) encrypts the stored IdP refresh tokens.
func New(codes repository.Code, sessions repository.Session, hooks Hooks, clients []Client, encryptionKey []byte, opts ...Option) (*Broker, error) {
	if codes == nil {
		return nil, errors.New("code repository must not be nil")
	}

	if sessions == nil {
		return nil, errors.New("session repository must not be nil")
	}

	if hooks.Authenticate == nil {
		return nil, errors.New("hooks.Authenticate must not be nil")
	}

	if hooks.Mint == nil {
		return nil, errors.New("hooks.Mint must not be nil")
	}

	registered, err := validateClients(clients)
	if err != nil {
		return nil, err
	}

	b := &Broker{
		codes:         codes,
		sessions:      sessions,
		hooks:         hooks,
		clients:       registered,
		codeTTL:       defaultCodeTTL,
		sessionTTL:    defaultSessionTTL,
		rotationGrace: defaultRotationGrace,
		now:           time.Now,
	}
	if err := options.ApplyE(b, opts...); err != nil {
		return nil, err
	}

	b.sealer, err = newSealer(encryptionKey, b.deprecatedKeys...)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func validateClients(clients []Client) (map[string]Client, error) {
	if len(clients) == 0 {
		return nil, errors.New("at least one client is required")
	}

	out := make(map[string]Client, len(clients))

	for _, c := range clients {
		if c.ID == "" {
			return nil, errors.New("client id must not be empty")
		}

		if _, dup := out[c.ID]; dup {
			return nil, fmt.Errorf("duplicate client id %q", c.ID)
		}

		if len(c.RedirectURIs) == 0 {
			return nil, fmt.Errorf("client %q: at least one redirect uri is required", c.ID)
		}

		for _, raw := range c.RedirectURIs {
			u, err := url.Parse(raw)
			if err != nil {
				return nil, fmt.Errorf("client %q: parse redirect uri: %w", c.ID, err)
			}

			if u.Scheme == "" {
				return nil, fmt.Errorf("client %q: redirect uri %q has no scheme", c.ID, raw)
			}

			if u.Fragment != "" || strings.Contains(raw, "#") {
				return nil, fmt.Errorf("client %q: redirect uri %q has a fragment", c.ID, raw)
			}
		}

		out[c.ID] = Client{ID: c.ID, RedirectURIs: slices.Clone(c.RedirectURIs)}
	}

	return out, nil
}

// Attach hands the broker the RP it logs in and refreshes through. It
// fails unless OnAuthenticated, OnRedirect and OnLoginError were all taken
// from this broker: a missing wrapper would silently send native logins
// down the web path. It only sees that the wrappers were created, not that
// they reached rp: pass them to oidc.New. Until Attach succeeds the
// handlers answer 500.
func (b *Broker) Attach(rp *oidc.RP) error {
	if rp == nil {
		return errors.New("rp must not be nil")
	}

	b.wrapMu.Lock()
	defer b.wrapMu.Unlock()

	var missing []string
	if !b.wrappedAuth {
		missing = append(missing, "OnAuthenticated")
	}

	if !b.wrappedRedirect {
		missing = append(missing, "OnRedirect")
	}

	if !b.wrappedLoginError {
		missing = append(missing, "OnLoginError")
	}

	if len(missing) > 0 {
		return fmt.Errorf("native broker: pass the broker's %s wrapper(s) to oidc.New before Attach", strings.Join(missing, ", "))
	}

	b.rp.Store(rp)

	return nil
}

// Handlers groups the broker's HTTP handlers.
type Handlers struct {
	// Authorize starts a native login (GET).
	Authorize http.Handler
	// Token redeems codes and refresh tokens (POST).
	Token http.Handler
	// Revoke ends a refresh session (POST, RFC 7009).
	Revoke http.Handler
}

// Handlers returns the broker's HTTP handlers. They answer 500
// server_error until Attach succeeded.
func (b *Broker) Handlers() Handlers {
	return Handlers{
		Authorize: b.attached(b.handleAuthorize),
		Token:     b.attached(b.handleToken),
		Revoke:    b.attached(b.handleRevoke),
	}
}

func (b *Broker) attached(h func(http.ResponseWriter, *http.Request, *oidc.RP)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rp := b.rp.Load()
		if rp == nil {
			writeError(w, http.StatusInternalServerError, errServerError, "broker not attached")
			return
		}

		h(w, r, rp)
	})
}

// client returns the registered client and whether redirectURI is one of
// its redirect URIs.
func (b *Broker) client(clientID, redirectURI string) (Client, bool, bool) {
	c, ok := b.clients[clientID]
	if !ok {
		return Client{}, false, false
	}

	return c, true, slices.Contains(c.RedirectURIs, redirectURI)
}

func (b *Broker) logError(r *http.Request, stage string, err error) {
	if b.errorLogger != nil {
		b.errorLogger(r, stage, err)
	}
}

// nativeRedirectURL merges params into redirectURI's query. String
// concatenation would break URIs that already have a query.
func nativeRedirectURL(redirectURI string, params url.Values) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("parse redirect uri: %w", err)
	}

	q := u.Query()
	maps.Copy(q, params)

	u.RawQuery = q.Encode()

	return u.String(), nil
}
