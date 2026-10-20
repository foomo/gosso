package repository

import (
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// DefaultSessionIndices are the indexes NewDefaultSession creates.
var DefaultSessionIndices = []mongo.IndexModel{
	EntityIndex,
	ExpiresAtTTLIndex,
}
