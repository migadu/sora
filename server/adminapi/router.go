package adminapi

import (
	"net/http"
	"strings"
)

// extractPathParam extracts a path parameter from the URL
// For example, from "/admin/accounts/user@example.com" with prefix "/admin/accounts/"
// it extracts "user@example.com"
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
