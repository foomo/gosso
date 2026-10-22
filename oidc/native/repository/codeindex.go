package repository

import (
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// DefaultCodeIndices are the indexes NewDefaultCode creates.
var DefaultCodeIndices = []mongo.IndexModel{
	EntityIndex,
	ExpiresAtTTLIndex,
}
