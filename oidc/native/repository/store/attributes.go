package store

// Attributes are opaque consumer data returned by the broker's
// Hooks.Authenticate and stored on codes and sessions.
type Attributes map[string]string
