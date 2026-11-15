package userapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A script over max_script_size is refused with 413, as documented, also when its
// request body is over the cap on what the handler reads: that used to fail the JSON
// decode and answer 400 "Invalid request body".
func TestPutFilterOversizedScriptIs413(t *testing.T) {
	s := &Server{name: "user-api"}
	for name, tc := range map[string]struct {
		size    int
		message string
	}{
		"script over max_script_size":    {maxSieveScriptSize + 1, "Script exceeds maximum size"},
		"request body over the read cap": {maxSieveScriptRequestSize + 1, "Request body exceeds maximum size"},
	} {
		t.Run(name, func(t *testing.T) {
			body := `{"script":"` + strings.Repeat("a", tc.size) + `"}`
			req := httptest.NewRequest(http.MethodPut, "/user/filters/big", strings.NewReader(body))
			req = req.WithContext(context.WithValue(req.Context(), contextKeyAccountID, int64(1)))
			rec := httptest.NewRecorder()
			s.handlePutFilter(rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413; body %s", rec.Code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), tc.message) {
				t.Fatalf("response %s, want %q", rec.Body.String(), tc.message)
			}
		})
	}
}

// A script whose JSON string decodes to a NUL byte (e.g. \u0000 inside a comment or
// string) must be refused by ValidateScript with 400 Bad Request before reaching the
// database, rather than failing PostgreSQL text encoding (SQLSTATE 22021) with 500.
func TestPutFilterNULInScriptIs400(t *testing.T) {
	s := &Server{name: "user-api"}
	for _, tc := range []struct {
		name string
		body string
	}{
		{"NUL in hash comment", `{"script":"# \u0000\nkeep;\n"}`},
		{"NUL in bracket comment", `{"script":"/* \u0000 */\nkeep;\n"}`},
		{"NUL in quoted string", `{"script":"require \"fileinto\";\nfileinto \"INBOX\u0000\";\n"}`},
		{"NUL in text block", `{"script":"require \"vacation\";\nvacation text:\naway \u0000\n.\n;\n"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handlePutFilter bypassed validation and reached nil rdb (%v), want 400 Bad Request", r)
				}
			}()
			req := httptest.NewRequest(http.MethodPut, "/user/filters/vacation", strings.NewReader(tc.body))
			req = req.WithContext(context.WithValue(req.Context(), contextKeyAccountID, int64(1)))
			rec := httptest.NewRecorder()
			s.handlePutFilter(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), "Script validation failed:") {
				t.Fatalf("response %s, want Script validation failed", rec.Body)
			}
		})
	}
}
