package repository

import (
	"context"
	"errors"
	"time"

	keelpersistence "github.com/foomo/keel/persistence"
	keelmongo "github.com/foomo/keel/persistence/mongo"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/foomo/gosso/oidc/native/repository/store"
)

// DefaultSessionName is the collection NewDefaultSession uses.
var DefaultSessionName = "gosso_native_sessions"

type (
	// BaseSession is a Session repository on a keelmongo collection.
	BaseSession struct {
		collection *keelmongo.Collection
	}
	sessionDocument struct {
		ID                  string            `bson:"id"`
		ClientID            string            `bson:"clientID"`
		RefreshHash         string            `bson:"refreshHash"`
		PreviousRefreshHash string            `bson:"previousRefreshHash,omitempty"`
		RotatedAt           time.Time         `bson:"rotatedAt"`
		Subject             subjectDocument   `bson:"subject"`
		Attributes          map[string]string `bson:"attributes,omitempty"`
		IDPRefreshToken     tokenDocument     `bson:"idpRefreshToken"`
		CreatedAt           time.Time         `bson:"createdAt"`
		LastUsedAt          time.Time         `bson:"lastUsedAt"`
		ExpiresAt           time.Time         `bson:"expiresAt"`
	}
)

var _ Session = (*BaseSession)(nil)

// ------------------------------------------------------------------------------------------------
// ~ Constructor
// ------------------------------------------------------------------------------------------------

// NewSession returns a BaseSession on collection, which must carry
// DefaultSessionIndices or equivalents.
func NewSession(collection *keelmongo.Collection) *BaseSession {
	return &BaseSession{
		collection: collection,
	}
}

// NewDefaultSession opens DefaultSessionName with DefaultSessionIndices.
func NewDefaultSession(persistor *keelmongo.Persistor) (*BaseSession, error) {
	if persistor == nil {
		return nil, errors.New("persistor must not be nil")
	}

	col, err := persistor.Collection(
		DefaultSessionName,
		keelmongo.CollectionWithIndexes(DefaultSessionIndices...),
		keelmongo.CollectionWithIndexesMaxTime(time.Minute),
	)
	if err != nil {
		return nil, err
	}

	return NewSession(col), nil
}

// ------------------------------------------------------------------------------------------------
// ~ Getter
// ------------------------------------------------------------------------------------------------

func (r *BaseSession) Collection() *keelmongo.Collection {
	return r.collection
}

// ------------------------------------------------------------------------------------------------
// ~ Public methods
// ------------------------------------------------------------------------------------------------

// Create stores a new session.
func (r *BaseSession) Create(ctx context.Context, s store.Session) error {
	return r.collection.Insert(ctx, toSessionDocument(s))
}

// Get loads a session.
func (r *BaseSession) Get(ctx context.Context, id string) (store.Session, error) {
	var d sessionDocument
	if err := r.collection.Get(ctx, id, &d); errors.Is(err, keelpersistence.ErrNotFound) {
		return store.Session{}, ErrNotFound
	} else if err != nil {
		return store.Session{}, err
	}

	return store.Session{
		ID:                  d.ID,
		ClientID:            d.ClientID,
		RefreshHash:         d.RefreshHash,
		PreviousRefreshHash: d.PreviousRefreshHash,
		RotatedAt:           d.RotatedAt,
		Subject:             fromSubjectDocument(d.Subject),
		Attributes:          attributes(d.Attributes),
		IDPRefreshToken:     store.EncryptedToken(d.IDPRefreshToken),
		CreatedAt:           d.CreatedAt,
		LastUsedAt:          d.LastUsedAt,
		ExpiresAt:           d.ExpiresAt,
	}, nil
}

// Rotate replaces the session iff its stored refresh hash still equals
// expectedHash.
func (r *BaseSession) Rotate(ctx context.Context, s store.Session, expectedHash string) error {
	// a compare-and-swap on refreshHash, which keelmongo's version-based
	// Upsert does not express
	res, err := r.collection.Col().ReplaceOne(ctx,
		bson.D{{Key: "id", Value: s.ID}, {Key: "refreshHash", Value: expectedHash}},
		toSessionDocument(s),
	)
	if err != nil {
		return err
	}

	if res.MatchedCount == 0 {
		return ErrConflict
	}

	return nil
}

// Delete removes a session; a missing one is not an error.
func (r *BaseSession) Delete(ctx context.Context, id string) error {
	if err := r.collection.Delete(ctx, id); errors.Is(err, keelpersistence.ErrNotFound) {
		return nil
	} else {
		return err
	}
}

// ------------------------------------------------------------------------------------------------
// ~ keelmongo.Entity
// ------------------------------------------------------------------------------------------------

func (d *sessionDocument) GetID() string {
	return d.ID
}

func (d *sessionDocument) SetID(id string) {
	d.ID = id
}

// ------------------------------------------------------------------------------------------------
// ~ Private methods
// ------------------------------------------------------------------------------------------------

func toSessionDocument(s store.Session) *sessionDocument {
	return &sessionDocument{
		ID:                  s.ID,
		ClientID:            s.ClientID,
		RefreshHash:         s.RefreshHash,
		PreviousRefreshHash: s.PreviousRefreshHash,
		RotatedAt:           s.RotatedAt,
		Subject:             toSubjectDocument(s.Subject),
		Attributes:          s.Attributes,
		IDPRefreshToken:     tokenDocument(s.IDPRefreshToken),
		CreatedAt:           s.CreatedAt,
		LastUsedAt:          s.LastUsedAt,
		ExpiresAt:           s.ExpiresAt,
	}
}
