package userapi

import (
	"net/http"
	"net/url"
	"strings"
)

// extractPathParam extracts a path parameter from the URL
// For example, from "/user/mailboxes/INBOX/messages" with prefix "/user/mailboxes/"
// and suffix "/messages", it extracts "INBOX"
func extractPathParam(path, prefix, suffix string) string {
	// Remove prefix
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	remaining := strings.TrimPrefix(path, prefix)

	// If there's a suffix, remove it
	if suffix != "" {
		if !strings.HasSuffix(remaining, suffix) {
			return ""
		}
		remaining = strings.TrimSuffix(remaining, suffix)
	}

	return remaining
}

// pathName returns the mailbox or script name between prefix and suffix in r's
// path, percent-decoded exactly once. It cuts the escaped path, so an encoded
// "/" (%2F) stays part of the name, and decodes it with PathUnescape: in a path
// "+" is a plus (RFC 3986), not the form encoding of a space. The routers that
// pick the endpoint by suffix must look at the escaped path too.
func pathName(r *http.Request, prefix, suffix string) (string, error) {
	return url.PathUnescape(extractPathParam(r.URL.EscapedPath(), prefix, suffix))
}

// extractLastPathSegment extracts the last segment from a path
// For example, from "/user/messages/123", it extracts "123"
func extractLastPathSegment(path string) string {
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

// routeHandler wraps an http.HandlerFunc with method checking
func routeHandler(method string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			// Allow OPTIONS for CORS preflight
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != method {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handler(w, r)
	}
}

// multiMethodHandler allows multiple HTTP methods for a single route
func multiMethodHandler(handlers map[string]http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			// Allow OPTIONS for CORS preflight
			w.WriteHeader(http.StatusOK)
			return
		}
		if handler, ok := handlers[r.Method]; ok {
			handler(w, r)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
