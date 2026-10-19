// Native-app demo: a CLI public client that logs in through the sandbox's
// native broker (OAuth 2.0 for native apps, RFC 8252 loopback redirect) with
// a stock OAuth2 library, then calls /app/whoami, refreshes, and revokes.
//
// Start the sandbox first (`make sandbox.up`, `make sandbox.run`), then run
// `make sandbox.app` (or `make sandbox.app ARGS=-demo-reuse`).
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
	"time"

	"golang.org/x/oauth2"
)

func main() {
	base := flag.String("base", "http://localhost:8080", "sandbox base URL")
	clientID := flag.String("client", "sandbox-cli", "native client_id")
	redirect := flag.String("redirect", "http://127.0.0.1:8090/callback", "loopback redirect URI")
	demoReuse := flag.Bool("demo-reuse", false, "replay the old refresh token to show reuse detection")
	pause := flag.Bool("pause", false, "wait for Enter before refreshing (end the IdP session meanwhile)")
	flag.Parse()

	if err := run(*base, *clientID, *redirect, *demoReuse, *pause); err != nil {
		log.Fatal(err)
	}
}

func step(n int, format string, args ...any) {
	fmt.Printf("%d. %s\n", n, fmt.Sprintf(format, args...))
}

func run(base, clientID, redirect string, demoReuse, pause bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cfg := &oauth2.Config{
		ClientID:    clientID,
		RedirectURL: redirect,
		Endpoint: oauth2.Endpoint{
			AuthURL:   base + "/oidc/app/authorize",
			TokenURL:  base + "/oidc/app/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	// 1. PKCE verifier + state, authorize URL
	verifier := oauth2.GenerateVerifier()
	state := randomState()
	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

	step(1, "open this URL in a browser and log in (alice / password):\n   %s", authURL)
	openBrowser(authURL)

	// 2. wait for the loopback redirect
	code, err := waitForCode(ctx, redirect, state)
	if err != nil {
		return err
	}

	step(2, "received code on %s", redirect)

	// 3. redeem the code
	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return fmt.Errorf("exchange: %w", err)
	}

	step(3, "token exchange OK: access token expires %s", tok.Expiry.Format(time.TimeOnly))

	// 4. call the API
	if err := whoami(ctx, base, tok.AccessToken); err != nil {
		return err
	}

	step(4, "whoami OK")

	if pause {
		fmt.Println("   paused: end alice's offline session in the Keycloak admin, then press Enter")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}

	// 5. refresh
	refreshed, err := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
	if err != nil {
		return fmt.Errorf("refresh: %w", err)
	}

	step(5, "refresh OK: refresh token changed: %t", refreshed.RefreshToken != tok.RefreshToken)

	// 6. call the API with the new token
	if err := whoami(ctx, base, refreshed.AccessToken); err != nil {
		return err
	}

	step(6, "whoami with refreshed token OK")

	// 7. reuse detection or revoke
	if demoReuse {
		// inside the rotation grace window (10s) the old token still works,
		// so concurrent refreshes from one app both succeed
		fmt.Println("   waiting 11s for the rotation grace window to close ...")
		time.Sleep(11 * time.Second)

		_, err := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
		step(7, "replaying the OLD refresh token: %s", describe(err))

		_, err = cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshed.RefreshToken}).Token()
		fmt.Printf("   the CURRENT refresh token now fails too (session revoked): %s\n", describe(err))

		return nil
	}

	if err := revoke(ctx, base, clientID, refreshed.RefreshToken); err != nil {
		return err
	}

	_, err = cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshed.RefreshToken}).Token()
	step(7, "revoked; refreshing again: %s", describe(err))

	return nil
}

// describe names the OAuth error, or says the call unexpectedly worked.
func describe(err error) string {
	var rerr *oauth2.RetrieveError
	if errors.As(err, &rerr) {
		return fmt.Sprintf("%s (%s) as expected", rerr.ErrorCode, rerr.ErrorDescription)
	}

	if err != nil {
		return err.Error()
	}

	return "unexpectedly succeeded"
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

func whoami(ctx context.Context, base, accessToken string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/app/whoami", nil)
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

func revoke(ctx context.Context, base, clientID, refreshToken string) error {
	form := url.Values{"token": {refreshToken}, "client_id": {clientID}}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/oidc/app/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}

	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke: %s", resp.Status)
	}

	return nil
}
