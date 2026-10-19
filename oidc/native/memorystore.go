package native

import (
	"context"
	"sync"
)

// MemoryStore is an in-memory Store for tests, sandboxes and single-instance
// deployments that accept losing all sessions on restart. Expired entries
// are not collected.
type MemoryStore struct {
	mu       sync.Mutex
	codes    map[string]Code
	sessions map[string]Session
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		codes:    map[string]Code{},
		sessions: map[string]Session{},
	}
}

func (m *MemoryStore) PutCode(_ context.Context, c Code) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.codes[c.Hash] = cloneCode(c)

	return nil
}

func (m *MemoryStore) TakeCode(_ context.Context, hash string) (Code, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.codes[hash]
	if !ok {
		return Code{}, ErrNotFound
	}

	delete(m.codes, hash)

	return c, nil
}

func (m *MemoryStore) CreateSession(_ context.Context, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[s.ID] = cloneSession(s)

	return nil
}

func (m *MemoryStore) GetSession(_ context.Context, id string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		return Session{}, ErrNotFound
	}

	return cloneSession(s), nil
}

func (m *MemoryStore) RotateSession(_ context.Context, s Session, expectedHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cur, ok := m.sessions[s.ID]
	if !ok || cur.RefreshHash != expectedHash {
		return ErrConflict
	}

	m.sessions[s.ID] = cloneSession(s)

	return nil
}

func (m *MemoryStore) DeleteSession(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, id)

	return nil
}
