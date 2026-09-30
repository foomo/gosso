package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testIDPSLOURL = "https://idp.example.com/slo"

func newTestServiceProvider(t *testing.T) saml.ServiceProvider {
	t.Helper()

	metadataURL, err := url.Parse("https://sp.example.com/saml/metadata")
	require.NoError(t, err)

	return saml.ServiceProvider{
		EntityID:    "https://sp.example.com/saml/metadata",
		MetadataURL: *metadataURL,
		IDPMetadata: &saml.EntityDescriptor{
			EntityID: "https://idp.example.com",
			IDPSSODescriptors: []saml.IDPSSODescriptor{{
				SSODescriptor: saml.SSODescriptor{
					SingleLogoutServices: []saml.Endpoint{{
						Binding:  saml.HTTPRedirectBinding,
						Location: testIDPSLOURL,
					}},
				},
			}},
		},
	}
}

// withTestSigning configures the service provider to sign its requests
// and returns the certificate to validate them against.
func withTestSigning(t *testing.T, sp *saml.ServiceProvider) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sp.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	sp.Key = key
	sp.Certificate = cert
	sp.SignatureMethod = dsig.RSASHA256SignatureMethod

	return cert
}

// decodeLogoutRequest reverses the redirect binding: base64, then
// DEFLATE, then the LogoutRequest XML.
func decodeLogoutRequest(t *testing.T, redirect *url.URL) *etree.Element {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(redirect.Query().Get("SAMLRequest"))
	require.NoError(t, err)

	xml, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	require.NoError(t, err)

	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(xml))
	require.NotNil(t, doc.Root())

	return doc.Root()
}

func sessionIndexOf(el *etree.Element) string {
	if v := el.FindElement("./SessionIndex"); v != nil {
		return v.Text()
	}

	return ""
}

func TestMakeRedirectLogoutRequest(t *testing.T) {
	t.Parallel()

	t.Run("carries the session index when given one", func(t *testing.T) {
		t.Parallel()

		sp := newTestServiceProvider(t)

		redirect, err := makeRedirectLogoutRequest(&sp, "alice", "_session-1")
		require.NoError(t, err)

		assert.Equal(t, testIDPSLOURL, redirect.Scheme+"://"+redirect.Host+redirect.Path)
		assert.Empty(t, redirect.Query().Get("RelayState"))

		el := decodeLogoutRequest(t, redirect)
		assert.Equal(t, "alice", el.FindElement("./NameID").Text())
		assert.Equal(t, "_session-1", sessionIndexOf(el))
	})

	t.Run("carries no session index without one", func(t *testing.T) {
		t.Parallel()

		sp := newTestServiceProvider(t)

		redirect, err := makeRedirectLogoutRequest(&sp, "alice", "")
		require.NoError(t, err)

		el := decodeLogoutRequest(t, redirect)
		assert.Equal(t, "alice", el.FindElement("./NameID").Text())
		assert.Nil(t, el.FindElement("./SessionIndex"))
	})

	// The request is signed before the session index is added, so this
	// asserts the signature was renewed to cover it.
	t.Run("signature covers the session index", func(t *testing.T) {
		t.Parallel()

		sp := newTestServiceProvider(t)
		cert := withTestSigning(t, &sp)

		redirect, err := makeRedirectLogoutRequest(&sp, "alice", "_session-1")
		require.NoError(t, err)

		validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{cert},
		})

		validated, err := validator.Validate(decodeLogoutRequest(t, redirect))
		require.NoError(t, err)
		assert.Equal(t, "_session-1", sessionIndexOf(validated))
	})
}

func TestHandleLogout_SendsSessionIndexFromHint(t *testing.T) {
	t.Parallel()

	var loggedOut bool

	sp := &SP{
		middleware: &samlsp.Middleware{ServiceProvider: newTestServiceProvider(t)},
		sloHintProvider: func(*http.Request) (string, string) {
			return "alice", "_session-1"
		},
		onLogout: func(context.Context, http.ResponseWriter, *http.Request) error {
			loggedOut = true
			return nil
		},
	}

	rec := httptest.NewRecorder()
	sp.handleLogout(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/saml/logout", nil))

	require.Equal(t, http.StatusFound, rec.Code)
	assert.True(t, loggedOut)

	redirect, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "_session-1", sessionIndexOf(decodeLogoutRequest(t, redirect)))
}
