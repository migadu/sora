package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestRemoteLookupHealthCheckSendsBearerToken: auth_token is documented to go with
// every request to the lookup endpoint. The health check runs every 30s per proxy;
// without the token it would be an unauthenticated request against an endpoint that
// requires one, and a 401 from the API's auth layer would pass as healthy.
func TestRemoteLookupHealthCheckSendsBearerToken(t *testing.T) {
	for _, tc := range []struct {
		token, want string
	}{
		{token: "test-token", want: "Bearer test-token"},
		{token: "", want: ""},
	} {
		got := make(chan string, 1)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got <- r.Header.Get("Authorization")
			w.WriteHeader(http.StatusNotFound)
		}))

		client := NewHTTPRemoteLookupClient(srv.URL+"/lookup?email=$email", time.Second, tc.token, 143,
			false, false, false, false, false, false, false, nil, nil)
		if err := client.HealthCheck(context.Background()); err != nil {
			t.Errorf("token %q: health check failed: %v", tc.token, err)
		}
		if h := <-got; h != tc.want {
			t.Errorf("token %q: health check sent Authorization %q, want %q", tc.token, h, tc.want)
		}
		srv.Close()
	}
}
