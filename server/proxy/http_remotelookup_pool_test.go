package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHTTPRemoteLookupPoolField covers how the "pool" field of a lookup answer is read:
// only when there is no "server" (an explicit server keeps its hard-pin meaning, so an
// API that starts naming pools stays compatible with answers that predate them), and an
// answer with neither is auth-only, exactly as before.
func TestHTTPRemoteLookupPoolField(t *testing.T) {
	cases := []struct {
		name         string
		response     map[string]any
		wantServer   string
		wantPool     string
		wantAuthOnly bool
	}{
		{
			name:       "pool only",
			response:   map[string]any{"address": "user@example.com", "pool": " sora1 "},
			wantPool:   "sora1",
			wantServer: "",
		},
		{
			name:       "server only is unchanged",
			response:   map[string]any{"address": "user@example.com", "server": "backend:143"},
			wantServer: "backend:143",
		},
		{
			name:       "server wins over pool",
			response:   map[string]any{"address": "user@example.com", "server": "backend:143", "pool": "sora1"},
			wantServer: "backend:143",
			wantPool:   "",
		},
		{
			name:         "neither is auth-only",
			response:     map[string]any{"address": "user@example.com"},
			wantAuthOnly: true,
		},
		{
			name:         "empty pool string is auth-only",
			response:     map[string]any{"address": "user@example.com", "pool": "", "server": nil},
			wantAuthOnly: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tc.response)
			}))
			defer srv.Close()

			client := NewHTTPRemoteLookupClient(srv.URL+"/lookup?email=$email", 5*time.Second, "", 143,
				false, false, true, false, false, false, false, nil, nil)
			// route-only: no password_hash in the answer, no password to verify
			info, result, err := client.LookupUserRouteWithOptions(context.Background(), "user@example.com", "", true)
			if err != nil {
				t.Fatalf("lookup error: %v", err)
			}
			if result != AuthSuccess {
				t.Fatalf("result = %v, want AuthSuccess", result)
			}
			if info.ServerAddress != tc.wantServer {
				t.Errorf("ServerAddress = %q, want %q", info.ServerAddress, tc.wantServer)
			}
			if info.PoolName != tc.wantPool {
				t.Errorf("PoolName = %q, want %q", info.PoolName, tc.wantPool)
			}
			if info.AuthOnlyMode != tc.wantAuthOnly {
				t.Errorf("AuthOnlyMode = %v, want %v", info.AuthOnlyMode, tc.wantAuthOnly)
			}
		})
	}
}
