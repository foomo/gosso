// Package sso provides the shared contract used by protocol-specific
// authentication adapters (SAML, OIDC) in this module.
//
// A consumer of this library plugs in one or more adapters (see the
// saml and oidc subpackages) and receives a Subject through the
// OnAuthenticated callback once authentication succeeds. The consumer
// is responsible for translating that Subject into its own session
// representation; this package stores nothing.
package sso
