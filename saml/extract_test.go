package saml

import (
	"testing"

	"github.com/crewjam/saml"
	"github.com/stretchr/testify/assert"
)

func TestParseAssertion(t *testing.T) {
	t.Parallel()

	a := &saml.Assertion{
		Subject: &saml.Subject{
			NameID: &saml.NameID{Value: "alice@example.com"},
		},
		AuthnStatements: []saml.AuthnStatement{{SessionIndex: "idx-123"}},
		AttributeStatements: []saml.AttributeStatement{{
			Attributes: []saml.Attribute{
				{
					Name:   AzureADAttributeMap.ExternalID,
					Values: []saml.AttributeValue{{Value: "oid-42"}},
				},
				{
					Name:   AzureADAttributeMap.Email,
					Values: []saml.AttributeValue{{Value: "alice@example.com"}},
				},
				{
					Name:   AzureADAttributeMap.Firstname,
					Values: []saml.AttributeValue{{Value: "Alice"}},
				},
				{
					Name:   AzureADAttributeMap.Lastname,
					Values: []saml.AttributeValue{{Value: "Doe"}},
				},
				{
					Name: AzureADAttributeMap.Groups,
					Values: []saml.AttributeValue{
						{Value: "ad-admins"},
						{Value: "ad-users"},
					},
				},
				{
					Name:   "noise",
					Values: []saml.AttributeValue{{Value: "ignored"}},
				},
			},
		}},
	}

	sub := parseAssertion(a, AzureADAttributeMap)
	assert.Equal(t, "oid-42", sub.ExternalID)
	assert.Equal(t, "alice@example.com", sub.Email)
	assert.Equal(t, "Alice", sub.Firstname)
	assert.Equal(t, "Doe", sub.Lastname)
	assert.Equal(t, []string{"ad-admins", "ad-users"}, sub.Groups)
	assert.Equal(t, "alice@example.com", sub.NameID)
	assert.Equal(t, "idx-123", sub.Raw.SessionIndex)
	assert.Same(t, a, sub.Raw.Assertion)
}

func TestParseAssertion_CustomMap(t *testing.T) {
	t.Parallel()

	custom := AttributeMap{
		ExternalID: "sub",
		Email:      "email",
		Firstname:  "given_name",
		Lastname:   "family_name",
		Groups:     "roles",
	}
	a := &saml.Assertion{
		AttributeStatements: []saml.AttributeStatement{{
			Attributes: []saml.Attribute{
				{Name: "sub", Values: []saml.AttributeValue{{Value: "u1"}}},
				{Name: "roles", Values: []saml.AttributeValue{{Value: "admin"}}},
			},
		}},
	}
	sub := parseAssertion(a, custom)
	assert.Equal(t, "u1", sub.ExternalID)
	assert.Equal(t, []string{"admin"}, sub.Groups)
}

func TestParseAssertion_Nil(t *testing.T) {
	t.Parallel()

	sub := parseAssertion(nil, AzureADAttributeMap)
	assert.Empty(t, sub.ExternalID)
	assert.Empty(t, sub.Groups)
	assert.Nil(t, sub.Raw.Assertion)
}
