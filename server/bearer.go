package server

import "net/http"

// UserAPIRealm is the realm of the User API's Bearer challenge. The User API backend and
// the User API proxy answer a refused token alike, so both send this one.
const UserAPIRealm = "user-api"

// The RFC 6750 section 3.1 error codes a Bearer challenge carries for a presented token
// that was refused.
const (
	// BearerInvalidToken: "The access token provided is expired, revoked, malformed, or
	// invalid for other reasons."
	BearerInvalidToken = "invalid_token"
	// BearerInsufficientScope: "The request requires higher privileges than provided by
	// the access token."
	BearerInsufficientScope = "insufficient_scope"
)

// SetBearerChallenge sets on h the WWW-Authenticate challenge for a request to a resource
// protected by bearer tokens of realm, refused for want of a usable token. RFC 9110
// section 15.5.2: "The server generating a 401 response MUST send a WWW-Authenticate
// header field (Section 11.6.1) containing at least one challenge applicable to the target
// resource." RFC 6750 section 3 asks for the header whenever "the protected resource
// request does not include authentication credentials or does not contain an access token
// that enables access to the protected resource", a 403 included, and gives the challenge
// the auth-scheme "Bearer" and a realm.
//
// errorCode is the reason a presented token was refused (BearerInvalidToken,
// BearerInsufficientScope), sent as error="..." (RFC 6750 section 3.1). It is "" for a
// request without a bearer token, which includes another auth-scheme such as Basic: RFC
// 6750 section 3.1, "If the request lacks any authentication information (e.g., the client
// was unaware that authentication is necessary or attempted using an unsupported
// authentication method), the resource server SHOULD NOT include an error code or other
// error information."
//
// realm and errorCode are constants of the caller, sent as they are inside the quoted
// strings.
func SetBearerChallenge(h http.Header, realm, errorCode string) {
	challenge := `Bearer realm="` + realm + `"`
	if errorCode != "" {
		challenge += `, error="` + errorCode + `"`
	}
	h.Set("WWW-Authenticate", challenge)
}
