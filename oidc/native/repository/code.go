package repository

import (
	"context"
	"errors"
	"time"

	keelmongo "github.com/foomo/keel/persistence/mongo"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/foomo/gosso/oidc/native/repository/store"
)

// DefaultCodeName is the collection NewDefaultCode uses.
var DefaultCodeName = "gosso_native_codes"

type (
	// BaseCode is a Code repository on a keelmongo collection.
	BaseCode struct {
		collection *keelmongo.Collection
	}
	codeDocument struct {
		Hash            string            `bson:"id"`
		ClientID        string            `bson:"clientID"`
		RedirectURI     string            `bson:"redirectURI"`
		CodeChallenge   string            `bson:"codeChallenge"`
		Subject         subjectDocument   `bson:"subject"`
		Attributes      map[string]string `bson:"attributes,omitempty"`
		IDPRefreshToken tokenDocument     `bson:"idpRefreshToken"`
		ExpiresAt       time.Time         `bson:"expiresAt"`
	}
)

var _ Code = (*BaseCode)(nil)

// ------------------------------------------------------------------------------------------------
// ~ Constructor
// ------------------------------------------------------------------------------------------------

// NewCode returns a BaseCode on collection, which must carry
// DefaultCodeIndices or equivalents.
func NewCode(collection *keelmongo.Collection) *BaseCode {
	return &BaseCode{
		collection: collection,
	}
}

// NewDefaultCode opens DefaultCodeName with DefaultCodeIndices.
func NewDefaultCode(persistor *keelmongo.Persistor) (*BaseCode, error) {
	if persistor == nil {
		return nil, errors.New("persistor must not be nil")
	}

	col, err := persistor.Collection(
		DefaultCodeName,
		keelmongo.CollectionWithIndexes(DefaultCodeIndices...),
		keelmongo.CollectionWithIndexesMaxTime(time.Minute),
	)
	if err != nil {
		return nil, err
	}

	return NewCode(col), nil
}

// ------------------------------------------------------------------------------------------------
// ~ Getter
// ------------------------------------------------------------------------------------------------

func (r *BaseCode) Collection() *keelmongo.Collection {
	return r.collection
}

// ------------------------------------------------------------------------------------------------
// ~ Public methods
// ------------------------------------------------------------------------------------------------

// Put stores a pending code.
func (r *BaseCode) Put(ctx context.Context, c store.Code) error {
	return r.collection.Insert(ctx, &codeDocument{
		Hash:            c.Hash,
		ClientID:        c.ClientID,
		RedirectURI:     c.RedirectURI,
		CodeChallenge:   c.CodeChallenge,
		Subject:         toSubjectDocument(c.Subject),
		Attributes:      c.Attributes,
		IDPRefreshToken: tokenDocument(c.IDPRefreshToken),
		ExpiresAt:       c.ExpiresAt,
	})
}

// Take finds and deletes the code with the given hash in one operation,
// so a code is redeemed at most once.
func (r *BaseCode) Take(ctx context.Context, hash string) (store.Code, error) {
	var d codeDocument
	// keelmongo's Delete does not return the document
	if err := r.collection.Col().FindOneAndDelete(ctx, bson.D{{Key: "id", Value: hash}}).Decode(&d); errors.Is(err, mongo.ErrNoDocuments) {
		return store.Code{}, ErrNotFound
	} else if err != nil {
		return store.Code{}, err
	}

	return store.Code{
		Hash:            d.Hash,
		ClientID:        d.ClientID,
		RedirectURI:     d.RedirectURI,
		CodeChallenge:   d.CodeChallenge,
		Subject:         fromSubjectDocument(d.Subject),
		Attributes:      attributes(d.Attributes),
		IDPRefreshToken: store.EncryptedToken(d.IDPRefreshToken),
		ExpiresAt:       d.ExpiresAt,
	}, nil
}

// ------------------------------------------------------------------------------------------------
// ~ keelmongo.Entity
// ------------------------------------------------------------------------------------------------

func (d *codeDocument) GetID() string {
	return d.Hash
}

func (d *codeDocument) SetID(id string) {
	d.Hash = id
}
