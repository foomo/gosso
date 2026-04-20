package saml

import (
	"github.com/crewjam/saml"

	sso "github.com/foomo/gosso"
)

// parseAssertion walks the AttributeStatements of the assertion and
// produces an sso.Subject keyed by the URIs in AttributeMap. Missing
// attributes are left as zero values; the first value wins when an
// attribute is repeated, except for Groups which collects all values.
func parseAssertion(a *saml.Assertion, am AttributeMap) sso.Subject[Payload] {
	sub := sso.Subject[Payload]{
		Raw: Payload{Assertion: a},
	}
	if a == nil {
		return sub
	}

	if a.Subject != nil && a.Subject.NameID != nil {
		sub.NameID = a.Subject.NameID.Value
	}

	if len(a.AuthnStatements) > 0 {
		sub.Raw.SessionIndex = a.AuthnStatements[0].SessionIndex
	}

	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			switch attr.Name {
			case am.ExternalID:
				sub.ExternalID = firstValue(attr.Values)
			case am.Email:
				sub.Email = firstValue(attr.Values)
			case am.Firstname:
				sub.Firstname = firstValue(attr.Values)
			case am.Lastname:
				sub.Lastname = firstValue(attr.Values)
			case am.Groups:
				for _, v := range attr.Values {
					if v.Value != "" {
						sub.Groups = append(sub.Groups, v.Value)
					}
				}
			}
		}
	}

	return sub
}

func firstValue(vs []saml.AttributeValue) string {
	for _, v := range vs {
		if v.Value != "" {
			return v.Value
		}
	}

	return ""
}
