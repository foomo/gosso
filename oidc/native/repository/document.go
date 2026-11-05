package repository

import (
	"github.com/foomo/gosso/oidc/native/repository/store"
)

// subjectDocument and tokenDocument are embedded in both code and session
// documents.
type (
	subjectDocument struct {
		ExternalID string   `bson:"externalID"`
		Email      string   `bson:"email,omitempty"`
		Firstname  string   `bson:"firstname,omitempty"`
		Lastname   string   `bson:"lastname,omitempty"`
		Groups     []string `bson:"groups,omitempty"`
	}
	tokenDocument struct {
		KeyID      string `bson:"keyID"`
		Ciphertext []byte `bson:"ciphertext"`
	}
)

func toSubjectDocument(s store.Subject) subjectDocument {
	return subjectDocument(s)
}

func fromSubjectDocument(d subjectDocument) store.Subject {
	s := store.Subject(d)
	if len(s.Groups) == 0 {
		s.Groups = nil
	}

	return s
}

func attributes(m map[string]string) store.Attributes {
	if len(m) == 0 {
		return nil
	}

	return m
}

func hashes(h []string) []string {
	if len(h) == 0 {
		return nil
	}

	return h
}
