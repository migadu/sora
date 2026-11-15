package userapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A login whose email is only blanks names no address: it is refused 400 like a login
// without an email, before any database lookup. The credential lookup trims the address
// and refuses an empty one with an error that is not "user not found", so the login used
// to be answered 503 (after retries), which a client takes for an outage. The server has
// no database, so the login must be answered before the handler reaches it.
func TestLoginWithABlankEmailIsRefused400(t *testing.T) {
	s := &Server{name: "test"}
	req := httptest.NewRequest(http.MethodPost, "/user/auth/login", strings.NewReader(`{"email":" \t ","password":"secret"}`))
	rec := httptest.NewRecorder()

	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("the login with a blank email went on to the database: %v", p)
			}
		}()
		s.handleLogin(rec, req)
	}()

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d (%q), want 400", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "Email and password are required" {
		t.Errorf("body %q, want {\"error\": \"Email and password are required\"}", rec.Body.String())
	}
}
