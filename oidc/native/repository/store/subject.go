package store

// Subject is the storable projection of sso.Subject kept on codes and
// sessions.
type Subject struct {
	ExternalID string
	Email      string
	Firstname  string
	Lastname   string
	Groups     []string
}
