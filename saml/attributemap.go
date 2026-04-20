package saml

// AttributeMap names the SAML attribute URIs that are read out of the
// assertion into sso.Subject's common fields. The defaults target Azure
// AD; consumers that use a different IdP can override individual URIs
// via WithAttributeMap.
type AttributeMap struct {
	ExternalID string
	Email      string
	Firstname  string
	Lastname   string
	Groups     string
}

// AzureADAttributeMap is the default attribute URI set used by Azure AD
// (and, conveniently, by Keycloak when configured with the Microsoft
// attribute mappers).
var AzureADAttributeMap = AttributeMap{
	ExternalID: "http://schemas.microsoft.com/identity/claims/objectidentifier",
	Email:      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
	Firstname:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
	Lastname:   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
	Groups:     "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
}
