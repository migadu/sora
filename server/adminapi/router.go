package adminapi

import (
	"maps"
	"net/http"
	"slices"
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
func (s *Server) routeHandler(method string, handler http.HandlerFunc) http.HandlerFunc {
	return s.multiMethodHandler(map[string]http.HandlerFunc{method: handler})
}

// multiMethodHandler allows multiple HTTP methods for a single route. It answers
// OPTIONS itself, and any other method the route does not serve with a 405.
func (s *Server) multiMethodHandler(handlers map[string]http.HandlerFunc) http.HandlerFunc {
	// The route's methods, OPTIONS included, for the Allow header.
	allow := strings.Join(append(slices.Sorted(maps.Keys(handlers)), http.MethodOptions), ", ")
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			// RFC 9110 section 9.3.7: a successful OPTIONS response SHOULD
			// send Allow.
			w.Header().Set("Allow", allow)
			w.WriteHeader(http.StatusOK)
			return
		}
		if handler, ok := handlers[r.Method]; ok {
			handler(w, r)
			return
		}
		// RFC 9110 section 15.5.6: a 405 MUST carry an Allow header listing
		// the target resource's currently supported methods.
		w.Header().Set("Allow", allow)
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// notFound answers a path no endpoint serves with the documented JSON error,
// in place of ServeMux's text/plain "404 page not found".
func (s *Server) notFound(w http.ResponseWriter, _ *http.Request) {
	s.writeError(w, http.StatusNotFound, "Not found")
}
