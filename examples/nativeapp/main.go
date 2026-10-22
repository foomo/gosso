// Native-app demo: a CLI public client that logs in through the sandbox's
// native broker (OAuth 2.0 for native apps, RFC 8252 loopback redirect) with
// a stock OAuth2 library. Each scenario checks its own expected outcome and
// exits non-zero when the broker misbehaves.
//
// Start the sandbox first (`make sandbox.up`, `make sandbox.run`), then run
// one of the `make sandbox.app*` targets.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// graceWait outlasts the broker's default 10s rotation grace window.
const graceWait = 11 * time.Second

var scenarios = map[string]func(context.Context, *client) error{
	"basic":      scenarioBasic,
	"reuse":      scenarioReuse,
	"concurrent": scenarioConcurrent,
	"outage":     scenarioOutage,
	"signout":    scenarioSignout,
	"restart":    scenarioRestart,
	"check":      scenarioCheck,
}

func main() {
	base := flag.String("base", "http://localhost:8080", "sandbox base URL")
	clientID := flag.String("client", "sandbox-cli", "native client_id")
	redirect := flag.String("redirect", "http://127.0.0.1:8090/callback", "loopback redirect URI")
	scenario := flag.String("scenario", "basic", "basic | reuse | concurrent | outage | signout | restart | check")
	flag.Parse()

	run, ok := scenarios[*scenario]
	if !ok {
		log.Fatalf("unknown scenario %q", *scenario)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	c := newClient(*base, *clientID, *redirect)

	fmt.Printf("〉scenario %s against %s\n", *scenario, *base)

	if err := run(ctx, c); err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("PASS")
}

// client is the native app: an oauth2.Config for the broker plus the
// sandbox URLs.
type client struct {
	base     string
	clientID string
	redirect string
	cfg      *oauth2.Config
	step     int
}

func newClient(base, clientID, redirect string) *client {
	return &client{
		base:     base,
		clientID: clientID,
		redirect: redirect,
		cfg: &oauth2.Config{
			ClientID:    clientID,
			RedirectURL: redirect,
			Endpoint: oauth2.Endpoint{
				AuthURL:   base + "/oidc/app/authorize",
				TokenURL:  base + "/oidc/app/token",
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
	}
}

func (c *client) logf(format string, args ...any) {
	c.step++
	fmt.Printf("%d. %s\n", c.step, fmt.Sprintf(format, args...))
}

// login runs the browser login and the code exchange.
func (c *client) login(ctx context.Context) (*oauth2.Token, error) {
	verifier := oauth2.GenerateVerifier()
	state := randomState()
	authURL := c.cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

	c.logf("open this URL in a browser and log in (alice / password):\n   %s", authURL)
	openBrowser(authURL)

	code, err := waitForCode(ctx, c.redirect, state)
	if err != nil {
		return nil, err
	}

	c.logf("received code on %s", c.redirect)

	tok, err := c.cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange: %w", err)
	}

	c.logf("token exchange OK: access token expires %s", tok.Expiry.Format(time.TimeOnly))

	if err := c.whoami(ctx, tok.AccessToken); err != nil {
		return nil, err
	}

	c.logf("whoami OK")

	return tok, nil
}

func (c *client) refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	return c.cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
}

// refreshOK refreshes and requires success.
func (c *client) refreshOK(ctx context.Context, refreshToken, what string) (*oauth2.Token, error) {
	tok, err := c.refresh(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}

	c.logf("%s OK: refresh token changed: %t", what, tok.RefreshToken != refreshToken)

	return tok, nil
}

// refreshFails refreshes and requires the given OAuth error.
func (c *client) refreshFails(ctx context.Context, refreshToken, wantCode, what string) error {
	_, err := c.refresh(ctx, refreshToken)
	if err := expectOAuthError(err, wantCode); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}

	c.logf("%s: %s as expected", what, wantCode)

	return nil
}

// revokeAndConfirm revokes the session and checks the token is dead.
func (c *client) revokeAndConfirm(ctx context.Context, refreshToken string) error {
	if err := c.revoke(ctx, refreshToken); err != nil {
		return err
	}

	c.logf("revoked")

	return c.refreshFails(ctx, refreshToken, "invalid_grant", "refresh after revoke")
}

// scenarioBasic: login, whoami, refresh, whoami, revoke.
func scenarioBasic(ctx context.Context, c *client) error {
	tok, err := c.login(ctx)
	if err != nil {
		return err
	}

	refreshed, err := c.refreshOK(ctx, tok.RefreshToken, "refresh")
	if err != nil {
		return err
	}

	if err := c.whoami(ctx, refreshed.AccessToken); err != nil {
		return err
	}

	c.logf("whoami with refreshed token OK")

	return c.revokeAndConfirm(ctx, refreshed.RefreshToken)
}

// scenarioReuse: replaying an old refresh token after the grace window
// revokes the whole session.
func scenarioReuse(ctx context.Context, c *client) error {
	tok, err := c.login(ctx)
	if err != nil {
		return err
	}

	refreshed, err := c.refreshOK(ctx, tok.RefreshToken, "refresh")
	if err != nil {
		return err
	}

	fmt.Printf("   waiting %s for the rotation grace window to close ...\n", graceWait)
	time.Sleep(graceWait)

	if err := c.refreshFails(ctx, tok.RefreshToken, "invalid_grant", "replay of the OLD refresh token"); err != nil {
		return err
	}

	return c.refreshFails(ctx, refreshed.RefreshToken, "invalid_grant", "CURRENT refresh token after reuse (session revoked)")
}

// scenarioConcurrent: two refreshes with the same token at once both
// succeed, and the response that completes last stays valid after the grace
// window.
func scenarioConcurrent(ctx context.Context, c *client) error {
	tok, err := c.login(ctx)
	if err != nil {
		return err
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		last *oauth2.Token
		errs []error
	)

	for i := range 2 {
		wg.Go(func() {
			got, err := c.refresh(ctx, tok.RefreshToken)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				errs = append(errs, fmt.Errorf("concurrent refresh %d: %w", i+1, err))
				return
			}

			last = got
		})
	}

	wg.Wait()

	if err := errors.Join(errs...); err != nil {
		return err
	}

	c.logf("two concurrent refreshes with the same token both succeeded")

	fmt.Printf("   waiting %s for the rotation grace window to close ...\n", graceWait)
	time.Sleep(graceWait)

	current, err := c.refreshOK(ctx, last.RefreshToken, "refresh with the last response's token")
	if err != nil {
		return err
	}

	return c.revokeAndConfirm(ctx, current.RefreshToken)
}

// scenarioOutage: an unreachable IdP answers 503 and keeps the session; the
// same refresh token works once the IdP is back.
func scenarioOutage(ctx context.Context, c *client) error {
	tok, err := c.login(ctx)
	if err != nil {
		return err
	}

	pause("in another terminal run `make sandbox.idp.stop`")

	if err := c.refreshFails(ctx, tok.RefreshToken, "temporarily_unavailable", "refresh while the IdP is down"); err != nil {
		return err
	}

	pause("now run `make sandbox.idp.start` (it returns once Keycloak is healthy)")

	fmt.Printf("   waiting %s so the retry is outside the grace window ...\n", graceWait)
	time.Sleep(graceWait)

	refreshed, err := c.refreshOK(ctx, tok.RefreshToken, "retry with the SAME refresh token")
	if err != nil {
		return err
	}

	return c.revokeAndConfirm(ctx, refreshed.RefreshToken)
}

// scenarioSignout: ending the session at the IdP ends the native session at
// its next refresh.
func scenarioSignout(ctx context.Context, c *client) error {
	tok, err := c.login(ctx)
	if err != nil {
		return err
	}

	pause("in another terminal run `make sandbox.idp.signout` (or sign out alice's offline session in the Keycloak admin, http://localhost:8081)")

	return c.refreshFails(ctx, tok.RefreshToken, "invalid_grant", "refresh after the IdP ended the session")
}

// scenarioRestart: sessions live in MongoDB, so they survive a restart of
// the service.
func scenarioRestart(ctx context.Context, c *client) error {
	tok, err := c.login(ctx)
	if err != nil {
		return err
	}

	pause("restart the demo app: Ctrl-C the `make sandbox.run` terminal, start it again and wait for \"sandbox listening\"")

	refreshed, err := c.refreshOK(ctx, tok.RefreshToken, "refresh after the restart")
	if err != nil {
		return err
	}

	return c.revokeAndConfirm(ctx, refreshed.RefreshToken)
}

func pause(msg string) {
	fmt.Printf("   ⏸  %s, then press Enter\n", msg)
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

// expectOAuthError checks err is an RFC 6749 error with the given code.
func expectOAuthError(err error, wantCode string) error {
	var rerr *oauth2.RetrieveError
	if errors.As(err, &rerr) {
		if rerr.ErrorCode == wantCode {
			return nil
		}

		return fmt.Errorf("want %s, got %s (%s)", wantCode, rerr.ErrorCode, rerr.ErrorDescription)
	}

	if err != nil {
		return fmt.Errorf("want %s, got %w", wantCode, err)
	}

	return fmt.Errorf("want %s, but the call succeeded", wantCode)
}

func randomState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)

	return base64.RawURLEncoding.EncodeToString(b)
}

func openBrowser(u string) {
	var cmd string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "linux":
		cmd = "xdg-open"
	default:
		return
	}

	_ = exec.Command(cmd, u).Start() //nolint:gosec // demo: opens the authorize URL we built
}

// waitForCode serves the loopback redirect URI until the browser lands on
// it, checks state and returns the code.
func waitForCode(ctx context.Context, redirect, state string) (string, error) {
	u, err := url.Parse(redirect)
	if err != nil {
		return "", fmt.Errorf("parse redirect: %w", err)
	}

	type result struct {
		code string
		err  error
	}

	done := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		var res result

		switch {
		case q.Get("state") != state:
			res.err = errors.New("state mismatch on the redirect")
		case q.Get("error") != "":
			res.err = fmt.Errorf("login failed: error=%s", q.Get("error"))
		default:
			res.code = q.Get("code")
		}

		if res.err != nil {
			http.Error(w, res.err.Error(), http.StatusBadRequest)
		} else {
			_, _ = io.WriteString(w, "logged in, you can close this tab and return to the terminal\n")
		}

		select {
		case done <- res:
		default:
		}
	})

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", u.Host)
	if err != nil {
		return "", fmt.Errorf("listen on %s: %w", u.Host, err)
	}

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	go func() { _ = srv.Serve(ln) }()

	defer func() { _ = srv.Shutdown(context.Background()) }()

	select {
	case res := <-done:
		return res.code, res.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func (c *client) whoami(ctx context.Context, accessToken string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/app/whoami", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("whoami: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("whoami: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	fmt.Printf("   %s\n", strings.TrimSpace(string(body)))

	return nil
}

func (c *client) revoke(ctx context.Context, refreshToken string) error {
	resp, err := c.postForm(ctx, "/oidc/app/revoke", url.Values{"token": {refreshToken}, "client_id": {c.clientID}})
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke: %s", resp.Status)
	}

	return nil
}

func (c *client) postForm(ctx context.Context, path string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return http.DefaultClient.Do(req)
}
