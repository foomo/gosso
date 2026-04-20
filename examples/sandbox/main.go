// Sandbox demo: one binary that mounts both the SAML and OIDC adapters
// against a local Keycloak. Run `make sandbox.up` first to start
// Keycloak, then `make sandbox.run` to start this app on
// http://localhost:8080.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	sso "github.com/foomo/gosso"
	"github.com/foomo/gosso/oidc"
	"github.com/foomo/gosso/saml"
)

const (
	appURL            = "http://localhost:8080"
	keycloakBaseURL   = "http://localhost:8081"
	realm             = "gosso-sandbox"
	oidcClientID      = "gosso-oidc"
	oidcClientSecret  = "dev-secret-do-not-use"
	sessionCookieName = "gosso_sandbox_session"
	certPath          = "sandbox/certs/sp.crt"
	keyPath           = "sandbox/certs/sp.key"
)

// subject is the normalised view we stash in the in-memory session.
// We keep only what we need to render; the raw SAML assertion / OIDC
// ID token are not JSON-friendly.
type subject struct {
	Protocol     string    `json:"protocol"`
	ExternalID   string    `json:"external_id"`
	Email        string    `json:"email"`
	Firstname    string    `json:"firstname"`
	Lastname     string    `json:"lastname"`
	Groups       []string  `json:"groups"`
	NameID       string    `json:"name_id,omitempty"`
	SessionIndex string    `json:"session_index,omitempty"`
	RawIDToken   string    `json:"raw_id_token,omitempty"`
	LoggedInAt   time.Time `json:"logged_in_at"`
}

type sessionStore struct {
	mu sync.Mutex
	m  map[string]subject
}

func newSessionStore() *sessionStore {
	return &sessionStore{m: make(map[string]subject)}
}

func (s *sessionStore) set(w http.ResponseWriter, sub subject) {
	id := randomID()
	s.mu.Lock()
	s.m[id] = sub
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *sessionStore) get(r *http.Request) (subject, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return subject{}, false
	}
	s.mu.Lock()
	sub, ok := s.m[c.Value]
	s.mu.Unlock()
	return sub, ok
}

func (s *sessionStore) clear(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookieName)
	if err == nil {
		s.mu.Lock()
		delete(s.m, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func randomID() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func main() {

	store := newSessionStore()

	samlSP, err := newSAMLSP(store)
	if err != nil {
		log.Fatalf("saml init: %v", err)
	}
	oidcRP, err := newOIDCRP(store)
	if err != nil {
		log.Fatalf("oidc init: %v", err)
	}

	mux := http.NewServeMux()

	// SAML
	samlH := samlSP.Handlers()
	mux.Handle("/saml/", samlH.ACS)          // /saml/metadata + /saml/acs
	mux.Handle("/saml/login", samlH.Login)   // redirects to IdP
	mux.Handle("/saml/logout", samlH.Logout) // fires OnLogout + SLO request
	mux.Handle("/saml/slo", samlH.SLO)       // handles the IdP's LogoutResponse

	// OIDC
	oidcH := oidcRP.Handlers()
	mux.Handle("/oidc/login", oidcH.Login)
	mux.Handle("/oidc/callback", oidcH.Callback)
	mux.Handle("/oidc/logout", oidcH.Logout)

	// Demo endpoints
	mux.HandleFunc("/", rootHandler(store))
	mux.HandleFunc("/whoami", whoamiHandler(store))
	mux.HandleFunc("/protected", protectedHandler(store))

	// Wrap the mux with otelhttp so every request is a server span; the
	// gosso adapters then attach their own child spans (oidc.callback,
	// saml.acs, ...) to it.
	handler := otelhttp.NewHandler(mux, "gosso-sandbox")

	log.Printf("sandbox listening on %s", appURL)
	log.Printf("  log in as alice / password or bob / password via SAML or OIDC")
	if err := http.ListenAndServe(":8080", handler); err != nil {
		log.Fatal(err)
	}
}

// bridgeErrorLogger routes gosso runtime errors to the sandbox's stderr
// logger. In a keel service you'd send these to `telemetry.Ctx(ctx).
// LogError(...)` or your zap logger instead.
func bridgeErrorLogger(r *http.Request, stage string, err error) {
	log.Printf("gosso error stage=%s path=%s: %v", stage, r.URL.Path, err)
}

func newSAMLSP(store *sessionStore) (*saml.SP, error) {
	metadataURL := fmt.Sprintf("%s/realms/%s/protocol/saml/descriptor", keycloakBaseURL, realm)
	cert, key, err := saml.LoadKeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load sp key pair: %w", err)
	}
	onAuth := func(_ context.Context, w http.ResponseWriter, _ *http.Request, s sso.Subject[saml.Payload]) error {
		store.set(w, subject{
			Protocol:     "saml",
			ExternalID:   s.ExternalID,
			Email:        s.Email,
			Firstname:    s.Firstname,
			Lastname:     s.Lastname,
			Groups:       s.Groups,
			NameID:       s.NameID,
			SessionIndex: s.Raw.SessionIndex,
			LoggedInAt:   time.Now(),
		})
		return nil
	}
	// Keycloak may still be starting up when the app launches; retry the
	// metadata fetch for up to a minute.
	var sp *saml.SP
	for i := 0; i < 20; i++ {
		sp, err = saml.New(
			appURL+"/saml/metadata",
			appURL,
			metadataURL,
			cert,
			key,
			onAuth,
			saml.WithAllowIDPInitiated(false),
			saml.WithOnLogout(func(_ context.Context, w http.ResponseWriter, r *http.Request) error {
				store.clear(w, r)
				return nil
			}),
			saml.WithPostLogoutRedirectURL(appURL+"/"),
			saml.WithSLOHintProvider(func(r *http.Request) (string, string) {
				sub, ok := store.get(r)
				if !ok {
					return "", ""
				}
				return sub.NameID, sub.SessionIndex
			}),
			saml.WithErrorLogger(bridgeErrorLogger),
		)
		if err == nil {
			return sp, nil
		}
		log.Printf("saml init attempt %d/20 failed: %v", i+1, err)
		time.Sleep(3 * time.Second)
	}
	return nil, err
}

func newOIDCRP(store *sessionStore) (*oidc.RP, error) {
	issuer := fmt.Sprintf("%s/realms/%s", keycloakBaseURL, realm)
	onAuth := func(_ context.Context, w http.ResponseWriter, _ *http.Request, s sso.Subject[oidc.Payload]) error {
		store.set(w, subject{
			Protocol:   "oidc",
			ExternalID: s.ExternalID,
			Email:      s.Email,
			Firstname:  s.Firstname,
			Lastname:   s.Lastname,
			Groups:     s.Groups,
			RawIDToken: s.Raw.RawIDToken,
			LoggedInAt: time.Now(),
		})
		return nil
	}
	var (
		rp  *oidc.RP
		err error
	)
	for i := 0; i < 20; i++ {
		rp, err = oidc.New(
			issuer,
			oidcClientID,
			oidcClientSecret,
			appURL+"/oidc/callback",
			[]byte("sandbox-not-for-production-use-only"),
			onAuth,
			oidc.WithExtraScopes("offline_access"),
			oidc.WithOnLogout(func(_ context.Context, w http.ResponseWriter, r *http.Request) error {
				store.clear(w, r)
				return nil
			}),
			oidc.WithLogoutHintProvider(func(r *http.Request) string {
				sub, ok := store.get(r)
				if !ok {
					return ""
				}
				return sub.RawIDToken
			}),
			oidc.WithPostLogoutRedirectURL(appURL+"/"),
			oidc.WithErrorLogger(bridgeErrorLogger),
		)
		if err == nil {
			return rp, nil
		}
		log.Printf("oidc init attempt %d/20 failed: %v", i+1, err)
		time.Sleep(3 * time.Second)
	}
	return nil, err
}

var rootTmpl = template.Must(template.New("root").Parse(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>gosso sandbox</title>
  <style>
    body { font-family: -apple-system, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; }
    h1 { margin-bottom: 0; }
    .sub { color: #888; margin-top: 0.25rem; }
    .card { border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-top: 1rem; }
    .pill { display: inline-block; padding: 2px 8px; border-radius: 10px; background: #eef; font-size: 12px; }
    a.btn { display: inline-block; padding: 8px 14px; border-radius: 6px; background: #4444ff; color: white; text-decoration: none; margin-right: 8px; }
    a.btn.red { background: #c0392b; }
    a.btn.ghost { background: transparent; color: #4444ff; border: 1px solid #4444ff; }
    pre { background: #f4f4f4; padding: 0.75rem; border-radius: 4px; overflow: auto; }
  </style>
</head>
<body>
  <h1>gosso sandbox</h1>
  <p class="sub">SAML + OIDC against Keycloak @ localhost:8081</p>

{{ if .LoggedIn }}
  <div class="card">
    <p>logged in as <strong>{{ .Sub.Firstname }} {{ .Sub.Lastname }}</strong> via <span class="pill">{{ .Sub.Protocol }}</span></p>
    <pre>{{ .SubJSON }}</pre>
    <p>
      <a class="btn red" href="/{{ .Sub.Protocol }}/logout">logout</a>
      <a class="btn ghost" href="/whoami">/whoami</a>
      <a class="btn ghost" href="/protected">/protected</a>
    </p>
  </div>
{{ else }}
  <div class="card">
    <p>not logged in. pick a protocol:</p>
    <p>
      <a class="btn" href="/saml/login?target=/">login via SAML</a>
      <a class="btn" href="/oidc/login?target=/">login via OIDC</a>
    </p>
    <p class="sub">users: <code>alice / password</code> (admins), <code>bob / password</code> (users)</p>
  </div>
{{ end }}
</body>
</html>`))

func rootHandler(store *sessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		sub, ok := store.get(r)
		data := struct {
			LoggedIn bool
			Sub      subject
			SubJSON  string
		}{LoggedIn: ok, Sub: sub}
		if ok {
			b, _ := json.MarshalIndent(sub, "", "  ")
			data.SubJSON = string(b)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = rootTmpl.Execute(w, data)
	}
}

func whoamiHandler(store *sessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub, ok := store.get(r)
		if !ok {
			http.Error(w, "no session", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sub)
	}
}

func protectedHandler(store *sessionStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sub, ok := store.get(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "hello %s %s — you reached the protected endpoint\n", sub.Firstname, sub.Lastname)
	}
}
