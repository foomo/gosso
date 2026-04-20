package oidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCodec(now time.Time) *transitCodec {
	return &transitCodec{
		name:       "gosso_test_transit",
		path:       "/callback",
		ttl:        5 * time.Minute,
		signingKey: []byte("unit-test-signing-key"),
		nowFunc:    func() time.Time { return now },
	}
}

func TestTransit_RoundTrip(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	c := newTestCodec(now)
	in := transitData{State: "s", Nonce: "n", CodeVerifier: "v", Target: "/x"}

	rec := httptest.NewRecorder()
	require.NoError(t, c.write(rec, in))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback", nil)
	for _, ck := range rec.Result().Cookies() {
		req.AddCookie(ck)
	}

	out, err := c.read(req)
	require.NoError(t, err)
	assert.Equal(t, in.State, out.State)
	assert.Equal(t, in.Nonce, out.Nonce)
	assert.Equal(t, in.CodeVerifier, out.CodeVerifier)
	assert.Equal(t, in.Target, out.Target)
	assert.Equal(t, now.Unix(), out.IssuedAt)
}

func TestTransit_TamperedPayload(t *testing.T) {
	t.Parallel()

	c := newTestCodec(time.Unix(1_700_000_000, 0))
	rec := httptest.NewRecorder()
	require.NoError(t, c.write(rec, transitData{State: "s"}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback", nil)
	orig := rec.Result().Cookies()[0]
	parts := strings.SplitN(orig.Value, ".", 2)
	require.Len(t, parts, 2)
	req.AddCookie(&http.Cookie{Name: c.name, Value: "AAAA." + parts[1]})
	_, err := c.read(req)
	assert.Error(t, err)
}

func TestTransit_TamperedSignature(t *testing.T) {
	t.Parallel()

	c := newTestCodec(time.Unix(1_700_000_000, 0))
	rec := httptest.NewRecorder()
	require.NoError(t, c.write(rec, transitData{State: "s"}))

	orig := rec.Result().Cookies()[0]
	parts := strings.SplitN(orig.Value, ".", 2)
	require.Len(t, parts, 2)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback", nil)
	req.AddCookie(&http.Cookie{Name: c.name, Value: parts[0] + ".tampered"})
	_, err := c.read(req)
	assert.Error(t, err)
}

func TestTransit_Expired(t *testing.T) {
	t.Parallel()

	start := time.Unix(1_700_000_000, 0)
	c := newTestCodec(start)
	rec := httptest.NewRecorder()
	require.NoError(t, c.write(rec, transitData{State: "s"}))

	// Advance beyond TTL.
	c.nowFunc = func() time.Time { return start.Add(10 * time.Minute) }

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback", nil)
	for _, ck := range rec.Result().Cookies() {
		req.AddCookie(ck)
	}

	_, err := c.read(req)
	assert.ErrorContains(t, err, "expired")
}

func TestTransit_KeyRotation(t *testing.T) {
	t.Parallel()

	old := &transitCodec{
		name: "k", path: "/callback", ttl: 5 * time.Minute,
		signingKey: []byte("old"),
		nowFunc:    func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	rec := httptest.NewRecorder()
	require.NoError(t, old.write(rec, transitData{State: "s"}))

	// Reader has rotated to a new primary key but still accepts the old
	// one as deprecated.
	reader := &transitCodec{
		name: "k", path: "/callback", ttl: 5 * time.Minute,
		signingKey:     []byte("new"),
		deprecatedKeys: [][]byte{[]byte("old")},
		nowFunc:        func() time.Time { return time.Unix(1_700_000_060, 0) },
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback", nil)
	for _, ck := range rec.Result().Cookies() {
		req.AddCookie(ck)
	}

	d, err := reader.read(req)
	require.NoError(t, err)
	assert.Equal(t, "s", d.State)
}
