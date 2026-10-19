package mongostore

import (
	"fmt"
	"sync/atomic"
	"testing"

	keelmongo "github.com/foomo/keel/persistence/mongo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/foomo/gosso/oidc/native"
	"github.com/foomo/gosso/oidc/native/nativetest"
)

// startMongo starts a MongoDB container and returns a factory for
// persistors, each on its own fresh database.
func startMongo(t *testing.T) func(t *testing.T) *keelmongo.Persistor {
	t.Helper()

	testcontainers.SkipIfProviderIsNotHealthy(t)

	container, err := mongodb.Run(t.Context(), "mongo:7")
	testcontainers.CleanupContainer(t, container)
	require.NoError(t, err)

	uri, err := container.ConnectionString(t.Context())
	require.NoError(t, err)

	var n atomic.Int32

	return func(t *testing.T) *keelmongo.Persistor {
		t.Helper()

		p, err := keelmongo.New(t.Context(), fmt.Sprintf("%s/gosso_test_%d", uri, n.Add(1)))
		require.NoError(t, err)

		t.Cleanup(func() { _ = p.Close(t.Context()) })

		return p
	}
}

func TestMongoStore(t *testing.T) {
	t.Parallel()

	newPersistor := startMongo(t)

	nativetest.TestStore(t, func(t *testing.T) native.Store {
		t.Helper()

		s, err := New(newPersistor(t))
		require.NoError(t, err)

		return s
	})
}

func TestMongoStore_TTLIndexes(t *testing.T) {
	t.Parallel()

	p := startMongo(t)(t)

	_, err := New(p, WithCodesCollection("c"), WithSessionsCollection("s"))
	require.NoError(t, err)

	for _, name := range []string{"c", "s"} {
		cursor, err := p.DB().Collection(name).Indexes().List(t.Context())
		require.NoError(t, err)

		var indexes []bson.M
		require.NoError(t, cursor.All(t.Context(), &indexes))

		var found bool

		for _, idx := range indexes {
			key, _ := idx["key"].(bson.M)
			if _, ok := key["expiresAt"]; !ok {
				continue
			}

			found = true

			assert.EqualValues(t, 0, idx["expireAfterSeconds"], name)
		}

		assert.True(t, found, "collection %s has an expiresAt TTL index", name)
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	s := &Store{}
	require.Error(t, WithCodesCollection("")(s))
	require.Error(t, WithSessionsCollection("")(s))
	require.NoError(t, WithCodesCollection("x")(s))
	assert.Equal(t, "x", s.codesName)

	_, err := New(nil)
	require.Error(t, err)
}
