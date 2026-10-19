package native_test

import (
	"testing"

	"github.com/foomo/gosso/oidc/native"
	"github.com/foomo/gosso/oidc/native/nativetest"
)

func TestMemoryStore(t *testing.T) {
	t.Parallel()

	nativetest.TestStore(t, func(*testing.T) native.Store { return native.NewMemoryStore() })
}
