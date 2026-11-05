// Package mongotest starts one MongoDB testcontainer per test binary and
// hands out keel persistors on fresh databases. Tests that use it need
// Docker.
package mongotest

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	keelmongo "github.com/foomo/keel/persistence/mongo"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
)

// Image is the MongoDB image the container runs.
const Image = "mongo:7"

var (
	once     sync.Once
	uri      string
	errStart error
	dbs      atomic.Int32
)

// Persistor returns a persistor on a database of its own, closed when t
// ends. The container outlives t: testcontainers' reaper removes it when
// the test binary exits.
func Persistor(t *testing.T) *keelmongo.Persistor {
	t.Helper()

	once.Do(func() {
		container, err := mongodb.Run(context.Background(), Image)
		if err != nil {
			errStart = err
			return
		}

		uri, errStart = container.ConnectionString(context.Background())
		// testcontainers returns the URI with a trailing slash
		uri = strings.TrimSuffix(uri, "/")
	})
	require.NoError(t, errStart, "start %s (is Docker running?)", Image)

	p, err := keelmongo.New(t.Context(), fmt.Sprintf("%s/gosso_test_%d", uri, dbs.Add(1)))
	require.NoError(t, err)

	t.Cleanup(func() { _ = p.Close(context.Background()) })

	return p
}
