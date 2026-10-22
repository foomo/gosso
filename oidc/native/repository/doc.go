// Package repository persists the native broker's one-time codes and
// refresh sessions. Code and Session are the interfaces the broker uses;
// BaseCode and BaseSession implement them on keel's mongo persistor. The
// entities live in the store subpackage.
//
// Each repository uses its own collection, keyed by keelmongo's "id" field,
// with a TTL index on expiresAt. The TTL indexes only collect garbage; the
// broker checks expiry itself.
//
//	codes, err := repository.NewDefaultCode(persistor)
//	sessions, err := repository.NewDefaultSession(persistor)
//	b, err := native.New(codes, sessions, hooks, clients, key)
package repository
