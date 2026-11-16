//go:build integration

package userapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// JSON may spell every ASCII character as a six-byte Unicode escape. Such a
// representation must not lower the decoded script limit the API advertises.
func TestPutFilterEscapedJSONKeepsDecodedScriptLimit(t *testing.T) {
	tc := setupTestServer(t)
	tc.JWTToken = tc.loginFor(t, tc.TestUser.Email, tc.TestUser.Password)

	resp := tc.makeRequest(t, http.MethodGet, "/user/filters/capabilities", nil)
	var capabilities struct {
		MaxScriptSize int `json:"max_script_size"`
	}
	parseJSON(t, resp, &capabilities)
	if capabilities.MaxScriptSize < 7 {
		t.Fatalf("invalid advertised script limit: %d", capabilities.MaxScriptSize)
	}

	for _, tcSize := range []struct {
		name          string
		extra, status int
	}{
		{"at-limit", 0, http.StatusOK},
		{"over-limit", 1, http.StatusRequestEntityTooLarge},
	} {
		t.Run(tcSize.name, func(t *testing.T) {
			letters := capabilities.MaxScriptSize + tcSize.extra - len("#\nkeep;")
			script := "#" + strings.Repeat("a", letters) + "\nkeep;"
			body := `{"script":"#` + strings.Repeat(`\u0061`, letters) + `\nkeep;"}`
			if len(body) <= 2*capabilities.MaxScriptSize+1024 {
				t.Fatal("fixture must exceed the former encoded request limit")
			}
			path := "/user/filters/escaped-" + tcSize.name
			req, err := http.NewRequest(http.MethodPut, tc.Server.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tc.JWTToken)
			resp, err := tc.HTTPClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tcSize.status {
				t.Fatalf("PUT %d decoded bytes (%d JSON bytes) = %d: %s, want %d", len(script), len(body), resp.StatusCode, data, tcSize.status)
			}
			stored := tc.makeRequest(t, http.MethodGet, path, nil)
			if tcSize.extra != 0 {
				stored.Body.Close()
				if stored.StatusCode != http.StatusNotFound {
					t.Fatalf("oversized script was stored: GET = %d", stored.StatusCode)
				}
				return
			}
			var result struct {
				Script string `json:"script"`
			}
			if err := json.NewDecoder(stored.Body).Decode(&result); err != nil {
				stored.Body.Close()
				t.Fatal(err)
			}
			stored.Body.Close()
			if result.Script != script {
				t.Fatalf("stored script differs: got %d bytes, want %d", len(result.Script), len(script))
			}
		})
	}
}
