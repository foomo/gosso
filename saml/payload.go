package saml

import (
	"github.com/crewjam/saml"
)

// Payload is the SAML-specific data carried in sso.Subject[Payload].Raw.
// It gives the consumer everything needed to build its own session and,
// later, initiate a single-logout round-trip.
type Payload struct {
	// Assertion is the full, validated SAML assertion as parsed by
	// crewjam/saml. Most consumers only need the derived Subject fields;
	// it is exposed for the rare cases that need custom claim lookups.
	Assertion *saml.Assertion
	// SessionIndex mirrors the corresponding XML attribute in the first
	// AuthnStatement of the assertion. The IdP requires it as part of a
	// SAML 2.0 LogoutRequest.
	SessionIndex string
}
