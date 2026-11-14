package userapiproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/server/userapi"
)

// errorBody decodes an error response of the User API: Content-Type application/json and
// a body that is one object holding a non-empty "error" string (docs/user-api.md, "Error
// Response Format"; components/responses in user_api_openapi.yaml).
func errorBody(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want \"application/json\" (body %q)", ct, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not JSON: %v", w.Body.String(), err)
	}
	msg, ok := body["error"].(string)
	if len(body) != 1 || !ok || msg == "" {
		t.Fatalf("body = %q, want {\"error\": \"<message>\"}", w.Body.String())
	}
	return msg
}

// Every error the proxy writes itself, without a backend having answered, has the shape
// the User API answers and documents for its errors, so a client reads it the way it
// reads the backend's (for example with res.json()).
func TestUserAPIProxy_OwnErrorsAreJSON(t *testing.T) {
	valid := corsTestToken(t, time.Hour)
	s, m := newCORSTestProxy(t, deadBackend(t), []string{corsTestOrigin})
	handler := s.setupHandler()

	for _, tc := range []struct {
		name        string
		maintenance []string // nil: loaded and empty
		notLoaded   bool
		method      string
		path        string
		token       string
		body        string
		want        int
	}{
		{name: "maintenance list not loaded", notLoaded: true, method: http.MethodGet, path: "/user/mailboxes", token: valid, want: http.StatusServiceUnavailable},
		{name: "no token", method: http.MethodGet, path: "/user/mailboxes", want: http.StatusUnauthorized},
		{name: "expired token", method: http.MethodGet, path: "/user/mailboxes", token: corsTestToken(t, -time.Hour), want: http.StatusUnauthorized},
		{name: "login body too large", method: http.MethodPost, path: "/user/auth/login", body: strings.Repeat("x", maxAuthBodyBytes+1), want: http.StatusRequestEntityTooLarge},
		{name: "no backend outside maintenance", maintenance: []string{"127.0.0.1"}, method: http.MethodGet, path: "/user/mailboxes", token: valid, want: http.StatusServiceUnavailable},
		{name: "backend unreachable", method: http.MethodGet, path: "/user/mailboxes", token: valid, want: http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.notLoaded {
				m.Set(tc.maintenance)
			}
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Origin", corsTestOrigin)
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if w.Code != tc.want {
				t.Fatalf("status %d, want %d (body %q)", w.Code, tc.want, w.Body.String())
			}
			errorBody(t, w)
			if got := w.Header().Get("Access-Control-Allow-Origin"); got != corsTestOrigin {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, corsTestOrigin)
			}
		})
	}
}

// A token the proxy refuses is answered as the backend answers the same token: the same
// status, Content-Type and body, so a client cannot tell which of the two refused it.
func TestUserAPIProxy_RefusedTokenIsAnsweredAsTheBackendAnswersIt(t *testing.T) {
	api, err := userapi.New(nil, userapi.ServerOptions{Name: "json-backend", JWTSecret: corsTestSecret})
	if err != nil {
		t.Fatalf("userapi.New: %v", err)
	}
	backend := api.SetupRoutes()
	s, m := newCORSTestProxy(t, deadBackend(t), nil) // never dialed: the token is refused first
	m.Set(nil)
	proxied := s.setupHandler()

	otherKey, err := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{
		Email:            "user@example.com",
		AccountID:        42,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
	}).SignedString([]byte("another-secret-key-at-least-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		header string // Authorization; "" sends none
	}{
		{"no authorization header", ""},
		{"not a bearer token", "Basic dXNlcjpwYXNz"},
		{"bearer without a token", "Bearer"},
		{"expired token", "Bearer " + corsTestToken(t, -time.Hour)},
		{"token signed with another key", "Bearer " + otherKey},
		{"malformed token", "Bearer not.a.jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			get := func(h http.Handler) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
				if tc.header != "" {
					r.Header.Set("Authorization", tc.header)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			direct, viaProxy := get(backend), get(proxied)
			if direct.Code != http.StatusUnauthorized || viaProxy.Code != http.StatusUnauthorized {
				t.Fatalf("backend %d, proxy %d; want 401 from both", direct.Code, viaProxy.Code)
			}
			if got, want := viaProxy.Header().Get("Content-Type"), direct.Header().Get("Content-Type"); got != want {
				t.Errorf("proxy's Content-Type = %q, want the backend's %q", got, want)
			}
			var got, want map[string]any
			if err := json.Unmarshal(direct.Body.Bytes(), &want); err != nil {
				t.Fatalf("backend's body %q: %v", direct.Body.String(), err)
			}
			if err := json.Unmarshal(viaProxy.Body.Bytes(), &got); err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("proxy's body = %q, want the backend's %q", viaProxy.Body.String(), direct.Body.String())
			}
		})
	}
}
