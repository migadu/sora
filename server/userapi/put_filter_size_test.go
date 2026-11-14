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
