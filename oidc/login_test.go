package oidc

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// loginTarget runs handleLogin for rawTarget and returns the target the
// transit cookie carries to the callback.
func loginTarget(t *testing.T, rawTarget string) string {
	t.Helper()

	codec := newTestCodec(time.Unix(1_700_000_000, 0))
	rp := &RP{
		transit: codec,
		oauth2Cfg: &oauth2.Config{
			ClientID: "client",
			Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/authorize"},
		},
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/login?target="+rawTarget, nil)
	rec := httptest.NewRecorder()
	rp.handleLogin(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	callback := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/callback", nil)
	for _, ck := range rec.Result().Cookies() {
		callback.AddCookie(ck)
	}

	td, err := codec.read(callback)
	require.NoError(t, err)

	return td.Target
}

func TestHandleLogin_TransitKeepsTargetQuery(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"/kasse?step=delivery&loginOrigin=checkout",
		loginTarget(t, "%2Fkasse%3Fstep%3Ddelivery%26loginOrigin%3Dcheckout"),
	)
}

func TestHandleLogin_UnsafeTargetFallsBack(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "/", loginTarget(t, "https%3A%2F%2Fevil.example%2F%3Fx%3D1"))
}
