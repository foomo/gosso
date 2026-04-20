// Package safepath provides open-redirect-safe URL target validation
// shared by the SAML and OIDC adapters.
package safepath

import (
	"net/url"
	"strings"
)

// Target returns raw if it is a safe, app-local path, otherwise "/". It
// rejects absolute URLs, scheme-relative URLs, paths not starting with
// a single "/", and anything containing backslashes or control
// characters.
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

	return p
}
