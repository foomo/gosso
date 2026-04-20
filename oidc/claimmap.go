package oidc

// ClaimMap names the OIDC claims that are copied into sso.Subject's
// common fields. The defaults target the core + profile + email scopes
// plus the widely-used `groups` claim.
type ClaimMap struct {
	ExternalID string
	Email      string
	Firstname  string
	Lastname   string
	Groups     string
}

// StandardClaimMap is the default mapping suitable for most OIDC IdPs
// (Keycloak, Okta, Auth0, Microsoft Entra ID with the `groups` claim
// enabled).
var StandardClaimMap = ClaimMap{
	ExternalID: "sub",
	Email:      "email",
	Firstname:  "given_name",
	Lastname:   "family_name",
	Groups:     "groups",
}
