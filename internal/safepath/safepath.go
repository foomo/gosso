// Package safepath provides open-redirect-safe URL target validation
// shared by the SAML and OIDC adapters.
package safepath

import (
	"encoding/json"
	"net/url"
	"strings"
)

// MaxLength bounds a target's length as a JSON string. Both adapters keep
// the target JSON-encoded in a cookie, and a browser silently drops a
// cookie over ~4 KB; JSON escapes &, < and > to six bytes each, so the
// raw length alone understates it. The bound leaves room for the rest of
// the cookie (the OIDC login context, crewjam's relay-state claims).
const MaxLength = 1024

// Target returns raw as a safe, app-local path with its query, otherwise
// "/". It rejects absolute URLs, scheme-relative URLs, paths not starting
// with a single "/", and anything containing backslashes or control
// characters.
//
// The query is kept verbatim: the redirect destination is fixed by the
// checked path, and callers carry state in the query (a step, an origin
// marker). The fragment is dropped; browsers never send it to the server.
//
// A target over MaxLength loses its query, and becomes "/" if the path
// alone is still too long, so an oversized target degrades the redirect
// instead of breaking the login.
//
// The backslash rejection matters because some browsers normalise "\"
// to "/" during URL resolution, which can turn a path like "/\evil.com"
// back into the scheme-relative "//evil.com".
func Target(raw string) string {
	if raw == "" {
		return "/"
	}

	if strings.ContainsAny(raw, "\\\x00\r\n\t") {
		return "/"
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}

	if u.Scheme != "" || u.Host != "" || u.Opaque != "" {
		return "/"
	}

	p := u.Path
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "/"
	}

	target := (&url.URL{Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}).String()
	if encodedLength(target) <= MaxLength {
		return target
	}

	path := (&url.URL{Path: u.Path, RawPath: u.RawPath}).String()
	if encodedLength(path) <= MaxLength {
		return path
	}

	return "/"
}

// encodedLength returns the length of s inside a JSON string.
func encodedLength(s string) int {
	b, err := json.Marshal(s)
	if err != nil {
		return len(s)
	}

	return len(b) - len(`""`)
}
