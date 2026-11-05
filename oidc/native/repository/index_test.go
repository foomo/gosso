package repository

import (
	"testing"

	keelmongo "github.com/foomo/keel/persistence/mongo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/foomo/gosso/internal/mongotest"
)

func TestIndexes(t *testing.T) {
	t.Parallel()

	p := mongotest.Persistor(t)

	codes, err := NewDefaultCode(p)
	require.NoError(t, err)

	sessions, err := NewDefaultSession(p)
	require.NoError(t, err)

	for _, col := range []*keelmongo.Collection{codes.Collection(), sessions.Collection()} {
		cursor, err := col.Col().Indexes().List(t.Context())
		require.NoError(t, err)

		var indexes []struct {
			Key                bson.D `bson:"key"`
			Unique             bool   `bson:"unique"`
			ExpireAfterSeconds *int32 `bson:"expireAfterSeconds"`
		}
		require.NoError(t, cursor.All(t.Context(), &indexes))

		var unique, ttl bool

		for _, idx := range indexes {
			if len(idx.Key) != 1 {
				continue
			}

			switch idx.Key[0].Key {
			case "id":
				unique = idx.Unique
			case "expiresAt":
				ttl = idx.ExpireAfterSeconds != nil && *idx.ExpireAfterSeconds == 0
			}
		}

		name := col.Col().Name()
		assert.True(t, unique, "%s has a unique id index", name)
		assert.True(t, ttl, "%s has an expiresAt TTL index", name)
	}
}

func TestNewDefault_NilPersistor(t *testing.T) {
	t.Parallel()

	_, err := NewDefaultCode(nil)
	require.Error(t, err)

	_, err = NewDefaultSession(nil)
	require.Error(t, err)
}
