package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/migadu/sora/pkg/resilient"
)

// An address whose local part holds a "/" (atext, RFC 5322 §3.2.3) is sent as %2F
// (RFC 3986 §2.2). The route must cut the address out of the escaped path before
// decoding it (RFC 3986 §2.4), or it answers for the address after the "/".
func TestUserConnectionsAddressWithSlash(t *testing.T) {
	s, err := New(&resilient.ResilientDatabase{}, ServerOptions{Name: "slash", APIKey: rwKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/admin/connections/user/a%2Fb@example.com", nil)
	r.Header.Set("Authorization", "Bearer "+rwKey)
	w := httptest.NewRecorder()
	s.setupRoutes().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", w.Code, w.Body.String())
	}
	var got struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	if got.Email != "a/b@example.com" {
		t.Errorf("email %q, want %q", got.Email, "a/b@example.com")
	}
}
