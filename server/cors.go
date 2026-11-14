package server

import "net/http"

// SetCORSHeaders adds to h the CORS response headers that allowedOrigins (a User API
// allowed_origins list) gives a request from origin ("" when the request has no Origin).
// An empty list sends none. The User API applies it to every response, and the User API
// proxy to the responses it writes itself, so both answer an origin alike.
func SetCORSHeaders(h http.Header, origin string, allowedOrigins []string) {
	if len(allowedOrigins) == 0 {
		return
	}
	// The first matching entry decides: "*" answers with a literal "*",
	// a listed origin is reflected with credentials.
	allowed := false
	wildcard := false
	for _, allowedOrigin := range allowedOrigins {
		if allowedOrigin == "*" {
			allowed = true
			wildcard = true
			break
		}
		if origin != "" && allowedOrigin == origin {
			allowed = true
			break
		}
	}
	// Fetch Standard, "CORS protocol and HTTP caches": a "*" is sent on
	// every response, CORS request or not, and needs no Vary; an answer
	// that depends on the request's Origin needs Vary: Origin on every
	// response, including the ones that do not reflect it, or a cache can
	// answer one origin with a response stored for another. The answer is
	// the same "*" for everyone only when "*" is the first entry.
	if allowedOrigins[0] != "*" {
		h.Add("Vary", "Origin")
	}

	if !allowed {
		return
	}
	h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	h.Set("Access-Control-Max-Age", "3600")
	// A cross-origin reader sees only the CORS-safelisted response
	// headers and the ones named here (Fetch Standard, "CORS filtered
	// response"): Retry-After on a 503 for a body not available yet,
	// Content-Disposition on /raw. Static, so it needs no Vary.
	h.Set("Access-Control-Expose-Headers", "Retry-After, Content-Disposition")
	if wildcard {
		// A wildcard origin must NOT be combined with credentials (CORS spec):
		// reflecting a concrete origin + Allow-Credentials lets any site make
		// credentialed cross-origin reads. Emit literal "*" without credentials.
		h.Set("Access-Control-Allow-Origin", "*")
	} else {
		// Specific configured origin: safe to reflect and allow credentials.
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
	}
}
