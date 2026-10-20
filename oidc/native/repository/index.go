package repository

import (
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var (
	// EntityIndex makes keelmongo's "id" field unique.
	EntityIndex = mongo.IndexModel{
		Keys:    bson.D{{Key: "id", Value: 1}},
		Options: options.Index().SetUnique(true),
	}
	// ExpiresAtTTLIndex removes a document once its expiresAt has passed.
	ExpiresAtTTLIndex = mongo.IndexModel{
		Keys:    bson.D{{Key: "expiresAt", Value: 1}},
		Options: options.Index().SetName("expiresAt_ttl").SetExpireAfterSeconds(0),
	}
)
