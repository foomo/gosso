package saml

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleLogin_RewritesURLForRequestTracker(t *testing.T) {
	t.Parallel()

	var captured *http.Request

	sp := &SP{
		startAuthFlow: func(_ http.ResponseWriter, r *http.Request) {
			captured = r
		},
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/saml/login?target=/dashboard", nil)
	sp.handleLogin(httptest.NewRecorder(), req)

	require.NotNil(t, captured)
	assert.Equal(t, "/dashboard", captured.URL.Path)
	assert.Empty(t, captured.URL.RawQuery)
}

func TestHandleLogin_UnsafeTargetFallsBack(t *testing.T) {
	t.Parallel()

	var captured *http.Request

	sp := &SP{
		startAuthFlow: func(_ http.ResponseWriter, r *http.Request) {
			captured = r
		},
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, `/saml/login?target=/\evil.example/`, nil)
	sp.handleLogin(httptest.NewRecorder(), req)

	require.NotNil(t, captured)
	assert.Equal(t, "/", captured.URL.Path)
}
