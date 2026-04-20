package sso

// GroupMapper translates raw IdP group identifiers into the consumer's
// application-specific role type. It is a convenience helper; consumers
// with different translation needs should skip it and roll their own.
type GroupMapper[R comparable] map[string]R

// Map returns the roles for every known group, preserving input order and
// deduplicating results. Unknown groups are silently skipped.
func (m GroupMapper[R]) Map(groups []string) []R {
	if len(m) == 0 || len(groups) == 0 {
		return nil
	}

	seen := make(map[R]struct{}, len(groups))

	out := make([]R, 0, len(groups))
	for _, g := range groups {
		r, ok := m[g]
		if !ok {
			continue
		}

		if _, dup := seen[r]; dup {
			continue
		}

		seen[r] = struct{}{}
		out = append(out, r)
	}

	return out
}
