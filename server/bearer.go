package server

import "net/http"

// UserAPIRealm is the realm of the User API's Bearer challenge. The User API backend and
// the User API proxy answer a refused token alike, so both send this one.
const UserAPIRealm = "user-api"

// SetBearerChallenge sets on h the WWW-Authenticate challenge of a 401 for a resource
// protected by bearer tokens of realm. RFC 9110 section 15.5.2: "The server generating a
// 401 response MUST send a WWW-Authenticate header field (Section 11.6.1) containing at
// least one challenge applicable to the target resource." RFC 6750 section 3 gives the
// challenge the auth-scheme "Bearer" and a realm. tokenRefused reports that the request
// presented a bearer token that was refused (expired, malformed, badly signed): the
// challenge then carries error="invalid_token" (RFC 6750 section 3.1). A request without
// one, which includes another auth-scheme such as Basic, gets none: RFC 6750 section 3.1,
// "If the request lacks any authentication information (e.g., the client was unaware that
// authentication is necessary or attempted using an unsupported authentication method),
// the resource server SHOULD NOT include an error code or other error information."
//
// realm is a constant of the caller, sent as it is inside the quoted string.
func SetBearerChallenge(h http.Header, realm string, tokenRefused bool) {
	challenge := `Bearer realm="` + realm + `"`
	if tokenRefused {
		challenge += `, error="invalid_token"`
	}
	h.Set("WWW-Authenticate", challenge)
}
