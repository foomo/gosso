package sso

// Subject is the authenticated principal handed to the consumer after a
// successful authentication round-trip. The T type parameter carries the
// protocol-specific raw payload (e.g. saml.Payload, oidc.Payload); the
// other fields are common across protocols so consumers can share session
// construction logic.
type Subject[T any] struct {
	// ExternalID is the stable IdP-side user identifier
	// (Azure AD objectidentifier, OIDC `sub`).
	ExternalID string
	Email      string
	Firstname  string
	Lastname   string
	// Groups holds the raw group identifiers as returned by the IdP.
	// Use GroupMapper to translate them into application roles.
	Groups []string
	// NameID is the SAML NameID; empty for OIDC and other non-SAML flows.
	NameID string
	// Raw carries the protocol-specific payload.
	Raw T
}
