package oidc

import (
	"fmt"
	"maps"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	sso "github.com/foomo/gosso"
)

// buildSubject merges ID token claims with the optional UserInfo claims
// and projects them into an sso.Subject via the configured ClaimMap.
// UserInfo claims, when present, override ID token claims on conflict.
// The subject's ExternalID is required: a zero value means the ID token
// lacked the configured external-id claim (typically `sub`) and login
// is rejected rather than silently keying sessions off "".
func buildSubject(idToken *gooidc.IDToken, rawIDToken string, token oauthToken, userInfo map[string]any, cm ClaimMap) (sso.Subject[Payload], error) {
	idClaims := map[string]any{}
	if idToken != nil {
		if err := idToken.Claims(&idClaims); err != nil {
			return sso.Subject[Payload]{}, fmt.Errorf("parse id token claims: %w", err)
		}
	}

	merged := idClaims
	maps.Copy(merged, userInfo)

	sub := sso.Subject[Payload]{
		ExternalID: stringClaim(merged, cm.ExternalID),
		Email:      stringClaim(merged, cm.Email),
		Firstname:  stringClaim(merged, cm.Firstname),
		Lastname:   stringClaim(merged, cm.Lastname),
		Groups:     stringSliceClaim(merged, cm.Groups),
		Raw: Payload{
			IDToken:      idToken,
			RawIDToken:   rawIDToken,
			AccessToken:  token.AccessToken,
			TokenExpiry:  token.Expiry,
			RefreshToken: token.RefreshToken,
			UserInfo:     userInfo,
		},
	}

	if sub.ExternalID == "" {
		return sso.Subject[Payload]{}, fmt.Errorf("id token missing %q claim", cm.ExternalID)
	}

	return sub, nil
}

func stringClaim(claims map[string]any, key string) string {
	if key == "" {
		return ""
	}

	v, ok := claims[key]
	if !ok {
		return ""
	}

	if s, ok := v.(string); ok {
		return s
	}

	return ""
}

func stringSliceClaim(claims map[string]any, key string) []string {
	if key == "" {
		return nil
	}

	v, ok := claims[key]
	if !ok {
		return nil
	}

	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}

		return out
	case string:
		if x == "" {
			return nil
		}

		// Some IdPs (and misconfigured Keycloak group mappers) return
		// groups as a single comma-separated string — split on comma so
		// consumers don't have to.
		if strings.ContainsRune(x, ',') {
			parts := strings.Split(x, ",")

			out := make([]string, 0, len(parts))
			for _, p := range parts {
				if p = strings.TrimSpace(p); p != "" {
					out = append(out, p)
				}
			}

			if len(out) == 0 {
				return nil
			}

			return out
		}

		return []string{x}
	default:
		return nil
	}
}
