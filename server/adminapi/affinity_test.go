package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/affinitycache"
)

// fakeAffinityManager holds affinities in a map, as the gossip affinity manager does.
type fakeAffinityManager struct {
	entries map[[2]string]string // {user, protocol} -> backend
}

func (m *fakeAffinityManager) SetBackend(username, backend, protocol string) {
	m.entries[[2]string{username, protocol}] = backend
}

func (m *fakeAffinityManager) GetBackend(username, protocol string) (string, bool) {
	backend, ok := m.entries[[2]string{username, protocol}]
	return backend, ok
}

func (m *fakeAffinityManager) DeleteBackend(username, protocol string) {
	delete(m.entries, [2]string{username, protocol})
}

func (m *fakeAffinityManager) GetStats(ctx context.Context) map[string]any {
	return map[string]any{"enabled": true, "total_entries": len(m.entries)}
}

func (m *fakeAffinityManager) List() []affinitycache.AffinityEntry {
	assigned := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	var list []affinitycache.AffinityEntry
	for k, backend := range m.entries {
		list = append(list, affinitycache.AffinityEntry{
			Username: k[0], Protocol: k[1], Backend: backend,
			AssignedAt: assigned, ExpiresAt: assigned.Add(24 * time.Hour), NodeID: "node-1",
		})
	}
	return list
}

func newAffinityTestServer(t *testing.T, am AffinityManager) http.Handler {
	t.Helper()
	s, err := New(nil, ServerOptions{Name: "affinity", APIKey: rwKey, AffinityManager: am})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s.setupRoutes()
}

func affinityRequest(t *testing.T, h http.Handler, method, target string) (int, []byte) {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	r.Header.Set("Authorization", "Bearer "+rwKey)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, w.Body.Bytes()
}

// GET /admin/affinity answers found: true with the backend (the documented 404 for a
// missing affinity stays), so a client can tell the answer apart from an empty body.
func TestAffinityGet_ReportsFound(t *testing.T) {
	am := &fakeAffinityManager{entries: map[[2]string]string{{"anna+tag@example.com", "imap"}: "192.0.2.21:143"}}
	h := newAffinityTestServer(t, am)

	q := url.Values{"user": {"anna+tag@example.com"}, "protocol": {"imap"}}
	code, body := affinityRequest(t, h, http.MethodGet, "/admin/affinity?"+q.Encode())
	if code != http.StatusOK {
		t.Fatalf("GET existing affinity: status %d %s, want 200", code, body)
	}
	var got AffinityGetResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding %s: %v", body, err)
	}
	want := AffinityGetResponse{User: "anna+tag@example.com", Protocol: "imap", Backend: "192.0.2.21:143", Found: true}
	if got != want {
		t.Errorf("GET existing affinity: got %+v (%s), want %+v", got, body, want)
	}

	q.Set("user", "nobody@example.com")
	if code, body := affinityRequest(t, h, http.MethodGet, "/admin/affinity?"+q.Encode()); code != http.StatusNotFound {
		t.Errorf("GET missing affinity: status %d %s, want 404", code, body)
	}
}

// GET /admin/affinity/list lists this node's affinities, optionally only those of one
// protocol or one backend.
func TestAffinityList(t *testing.T) {
	am := &fakeAffinityManager{entries: map[[2]string]string{
		{"anna@example.com", "imap"}:  "192.0.2.21:143",
		{"anna@example.com", "pop3"}:  "192.0.2.21:110",
		{"bob@example.com", "imap"}:   "192.0.2.22:143",
		{"carol@example.com", "imap"}: "192.0.2.21:143",
	}}
	h := newAffinityTestServer(t, am)

	type listed struct{ user, protocol, backend string }
	tests := []struct {
		name  string
		query url.Values
		want  []listed
	}{
		{"all", nil, []listed{
			{"anna@example.com", "imap", "192.0.2.21:143"},
			{"anna@example.com", "pop3", "192.0.2.21:110"},
			{"bob@example.com", "imap", "192.0.2.22:143"},
			{"carol@example.com", "imap", "192.0.2.21:143"},
		}},
		{"protocol", url.Values{"protocol": {"POP3"}}, []listed{
			{"anna@example.com", "pop3", "192.0.2.21:110"},
		}},
		{"backend", url.Values{"backend": {"192.0.2.21:143"}}, []listed{
			{"anna@example.com", "imap", "192.0.2.21:143"},
			{"carol@example.com", "imap", "192.0.2.21:143"},
		}},
		{"none", url.Values{"backend": {"192.0.2.99:143"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := "/admin/affinity/list"
			if tt.query != nil {
				target += "?" + tt.query.Encode()
			}
			code, body := affinityRequest(t, h, http.MethodGet, target)
			if code != http.StatusOK {
				t.Fatalf("GET %s: status %d %s, want 200", target, code, body)
			}
			var resp struct {
				Affinities []struct {
					User      string    `json:"user"`
					Protocol  string    `json:"protocol"`
					Backend   string    `json:"backend"`
					ExpiresAt time.Time `json:"expires_at"`
					NodeID    string    `json:"node_id"`
				} `json:"affinities"`
				Count int `json:"count"`
			}
			if err := json.Unmarshal(body, &resp); err != nil {
				t.Fatalf("decoding %s: %v", body, err)
			}
			var got []listed
			for _, a := range resp.Affinities {
				got = append(got, listed{a.User, a.Protocol, a.Backend})
				if a.ExpiresAt.IsZero() || a.NodeID != "node-1" {
					t.Errorf("entry %+v lacks the expiry or node of the affinity", a)
				}
			}
			if !slices.Equal(got, tt.want) || resp.Count != len(tt.want) {
				t.Errorf("GET %s: got %v (count %d), want %v in this order", target, got, resp.Count, tt.want)
			}
		})
	}
}

// The affinity endpoints answer errors as JSON, as the OpenAPI spec says, also when the
// user, protocol or backend they echo holds a '"': a local part may be a quoted-string
// (RFC 5322 §3.4.1), and a client parses the 404 of GET /admin/affinity as the answer
// for a missing affinity.
func TestAffinityErrorsAreJSON(t *testing.T) {
	am := &fakeAffinityManager{entries: map[[2]string]string{}}
	s, err := New(nil, ServerOptions{
		Name: "affinity", APIKey: rwKey, AffinityManager: am,
		ValidBackends: map[string][]string{"imap": {"192.0.2.21:143"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := s.setupRoutes()

	missing := url.Values{"user": {`"john doe"@example.com`}, "protocol": {"imap"}}
	tests := []struct {
		name, method, target, body string
		status                     int
		wantInError                string
	}{
		{"get missing", http.MethodGet, "/admin/affinity?" + missing.Encode(), "", http.StatusNotFound, `"john doe"@example.com`},
		{"set unknown backend", http.MethodPost, "/admin/affinity", `{"user":"anna@example.com","protocol":"imap","backend":"192.0.2.99:143\""}`, http.StatusBadRequest, `192.0.2.99:143"`},
		{"set no backends", http.MethodPost, "/admin/affinity", `{"user":"anna@example.com","protocol":"pop3","backend":"192.0.2.21:110"}`, http.StatusBadRequest, "pop3"},
		{"get without user", http.MethodGet, "/admin/affinity?protocol=imap", "", http.StatusBadRequest, "required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.target, strings.NewReader(tt.body))
			r.Header.Set("Authorization", "Bearer "+rwKey)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tt.status {
				t.Fatalf("status %d %s, want %d", w.Code, w.Body, tt.status)
			}
			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type %q, want application/json", ct)
			}
			var resp struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("error answer is not JSON: %v: %s", err, w.Body)
			}
			if !strings.Contains(resp.Error, tt.wantInError) {
				t.Errorf("error %q does not name %q", resp.Error, tt.wantInError)
			}
		})
	}
}
