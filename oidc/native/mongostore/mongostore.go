// Package mongostore is a MongoDB native.Store on keel's mongo persistor.
// Codes and sessions live in two collections with TTL indexes on
// expiresAt; the indexes only collect garbage, the broker checks expiry
// itself.
package mongostore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/foomo/go/options"
	keelmongo "github.com/foomo/keel/persistence/mongo"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	mongooptions "go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/foomo/gosso/oidc/native"
)

// fieldID is MongoDB's primary key field.
const fieldID = "_id"

const (
	defaultCodesCollection    = "gosso_native_codes"
	defaultSessionsCollection = "gosso_native_sessions"
)

// Store is a native.Store backed by MongoDB.
type Store struct {
	codesName    string
	sessionsName string
	codes        *mongo.Collection
	sessions     *mongo.Collection
}

var _ native.Store = (*Store)(nil)

// Option configures a Store.
type Option = options.OptionE[*Store]

// WithCodesCollection names the codes collection. Default
// "gosso_native_codes".
func WithCodesCollection(name string) Option {
	return func(s *Store) error {
		if name == "" {
			return errors.New("codes collection name must not be empty")
		}

		s.codesName = name

		return nil
	}
}

// WithSessionsCollection names the sessions collection. Default
// "gosso_native_sessions".
func WithSessionsCollection(name string) Option {
	return func(s *Store) error {
		if name == "" {
			return errors.New("sessions collection name must not be empty")
		}

		s.sessionsName = name

		return nil
	}
}

// New opens both collections and creates their TTL indexes on expiresAt.
func New(persistor *keelmongo.Persistor, opts ...Option) (*Store, error) {
	if persistor == nil {
		return nil, errors.New("persistor must not be nil")
	}

	s := &Store{codesName: defaultCodesCollection, sessionsName: defaultSessionsCollection}
	if err := options.ApplyE(s, opts...); err != nil {
		return nil, err
	}

	ttl := keelmongo.CollectionWithIndexes(mongo.IndexModel{
		Keys:    bson.D{{Key: "expiresAt", Value: 1}},
		Options: mongooptions.Index().SetName("expiresAt_ttl").SetExpireAfterSeconds(0),
	})

	codes, err := persistor.Collection(s.codesName, ttl)
	if err != nil {
		return nil, fmt.Errorf("codes collection: %w", err)
	}

	sessions, err := persistor.Collection(s.sessionsName, ttl)
	if err != nil {
		return nil, fmt.Errorf("sessions collection: %w", err)
	}

	s.codes, s.sessions = codes.Col(), sessions.Col()

	return s, nil
}

type subjectDoc struct {
	ExternalID string   `bson:"externalID"`
	Email      string   `bson:"email,omitempty"`
	Firstname  string   `bson:"firstname,omitempty"`
	Lastname   string   `bson:"lastname,omitempty"`
	Groups     []string `bson:"groups,omitempty"`
}

type tokenDoc struct {
	KeyID      string `bson:"keyID"`
	Ciphertext []byte `bson:"ciphertext"`
}

type codeDoc struct {
	Hash            string            `bson:"_id"`
	ClientID        string            `bson:"clientID"`
	RedirectURI     string            `bson:"redirectURI"`
	CodeChallenge   string            `bson:"codeChallenge"`
	Subject         subjectDoc        `bson:"subject"`
	Attributes      map[string]string `bson:"attributes,omitempty"`
	IDPRefreshToken tokenDoc          `bson:"idpRefreshToken"`
	ExpiresAt       time.Time         `bson:"expiresAt"`
}

type sessionDoc struct {
	ID                  string            `bson:"_id"`
	ClientID            string            `bson:"clientID"`
	RefreshHash         string            `bson:"refreshHash"`
	PreviousRefreshHash string            `bson:"previousRefreshHash,omitempty"`
	RotatedAt           time.Time         `bson:"rotatedAt"`
	Subject             subjectDoc        `bson:"subject"`
	Attributes          map[string]string `bson:"attributes,omitempty"`
	IDPRefreshToken     tokenDoc          `bson:"idpRefreshToken"`
	CreatedAt           time.Time         `bson:"createdAt"`
	LastUsedAt          time.Time         `bson:"lastUsedAt"`
	ExpiresAt           time.Time         `bson:"expiresAt"`
}

func toSubjectDoc(s native.Subject) subjectDoc {
	return subjectDoc(s)
}

func fromSubjectDoc(d subjectDoc) native.Subject {
	s := native.Subject(d)
	if len(s.Groups) == 0 {
		s.Groups = nil
	}

	return s
}

func attributes(m map[string]string) native.Attributes {
	if len(m) == 0 {
		return nil
	}

	return m
}

func (s *Store) PutCode(ctx context.Context, c native.Code) error {
	_, err := s.codes.InsertOne(ctx, codeDoc{
		Hash:            c.Hash,
		ClientID:        c.ClientID,
		RedirectURI:     c.RedirectURI,
		CodeChallenge:   c.CodeChallenge,
		Subject:         toSubjectDoc(c.Subject),
		Attributes:      c.Attributes,
		IDPRefreshToken: tokenDoc(c.IDPRefreshToken),
		ExpiresAt:       c.ExpiresAt,
	})

	return err
}

func (s *Store) TakeCode(ctx context.Context, hash string) (native.Code, error) {
	var d codeDoc
	if err := s.codes.FindOneAndDelete(ctx, bson.D{{Key: fieldID, Value: hash}}).Decode(&d); errors.Is(err, mongo.ErrNoDocuments) {
		return native.Code{}, native.ErrNotFound
	} else if err != nil {
		return native.Code{}, err
	}

	return native.Code{
		Hash:            d.Hash,
		ClientID:        d.ClientID,
		RedirectURI:     d.RedirectURI,
		CodeChallenge:   d.CodeChallenge,
		Subject:         fromSubjectDoc(d.Subject),
		Attributes:      attributes(d.Attributes),
		IDPRefreshToken: native.EncryptedToken(d.IDPRefreshToken),
		ExpiresAt:       d.ExpiresAt,
	}, nil
}

func toSessionDoc(s native.Session) sessionDoc {
	return sessionDoc{
		ID:                  s.ID,
		ClientID:            s.ClientID,
		RefreshHash:         s.RefreshHash,
		PreviousRefreshHash: s.PreviousRefreshHash,
		RotatedAt:           s.RotatedAt,
		Subject:             toSubjectDoc(s.Subject),
		Attributes:          s.Attributes,
		IDPRefreshToken:     tokenDoc(s.IDPRefreshToken),
		CreatedAt:           s.CreatedAt,
		LastUsedAt:          s.LastUsedAt,
		ExpiresAt:           s.ExpiresAt,
	}
}

func (s *Store) CreateSession(ctx context.Context, sess native.Session) error {
	_, err := s.sessions.InsertOne(ctx, toSessionDoc(sess))
	return err
}

func (s *Store) GetSession(ctx context.Context, id string) (native.Session, error) {
	var d sessionDoc
	if err := s.sessions.FindOne(ctx, bson.D{{Key: fieldID, Value: id}}).Decode(&d); errors.Is(err, mongo.ErrNoDocuments) {
		return native.Session{}, native.ErrNotFound
	} else if err != nil {
		return native.Session{}, err
	}

	return native.Session{
		ID:                  d.ID,
		ClientID:            d.ClientID,
		RefreshHash:         d.RefreshHash,
		PreviousRefreshHash: d.PreviousRefreshHash,
		RotatedAt:           d.RotatedAt,
		Subject:             fromSubjectDoc(d.Subject),
		Attributes:          attributes(d.Attributes),
		IDPRefreshToken:     native.EncryptedToken(d.IDPRefreshToken),
		CreatedAt:           d.CreatedAt,
		LastUsedAt:          d.LastUsedAt,
		ExpiresAt:           d.ExpiresAt,
	}, nil
}

func (s *Store) RotateSession(ctx context.Context, sess native.Session, expectedHash string) error {
	res, err := s.sessions.ReplaceOne(ctx,
		bson.D{{Key: fieldID, Value: sess.ID}, {Key: "refreshHash", Value: expectedHash}},
		toSessionDoc(sess),
	)
	if err != nil {
		return err
	}

	if res.MatchedCount == 0 {
		return native.ErrConflict
	}

	return nil
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.sessions.DeleteOne(ctx, bson.D{{Key: fieldID, Value: id}})
	return err
}
