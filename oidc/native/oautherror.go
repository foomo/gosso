package native

import (
	"encoding/json"
	"net/http"
)

// RFC 6749 §5.2 error codes (plus RFC 6749 §4.1.2.1 for authorize).
const (
	errInvalidRequest          = "invalid_request"
	errInvalidClient           = "invalid_client"
	errInvalidGrant            = "invalid_grant"
	errUnsupportedGrantType    = "unsupported_grant_type"
	errUnsupportedResponseType = "unsupported_response_type"
	errTemporarilyUnavailable  = "temporarily_unavailable"
	errServerError             = "server_error"
)

type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeJSON writes v with the headers RFC 6749 §5.1 requires on token
// responses.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		status = http.StatusInternalServerError
		body = []byte(`{"error":"server_error"}`)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeError writes an RFC 6749 §5.2 error response.
func writeError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, oauthError{Error: code, ErrorDescription: description})
}
