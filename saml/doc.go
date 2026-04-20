// Package saml implements a stateless SAML 2.0 Service Provider on top of
// github.com/crewjam/saml. After a successful assertion the parsed
// principal is handed to the consumer via a gosso.OnAuthenticated
// callback; this package never writes session cookies itself.
package saml
