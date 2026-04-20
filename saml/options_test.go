package saml

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithCertificatePEM_EmptyChainRejected(t *testing.T) {
	t.Parallel()

	sp := &SP{}
	err := WithCertificatePEM(nil, nil)(sp)
	require.Error(t, err)
}

func TestWithBootstrapTimeout_Positive(t *testing.T) {
	t.Parallel()

	sp := &SP{}
	err := WithBootstrapTimeout(0)(sp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "> 0")
}
