package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/migadu/sora/server"
)

// GET /admin/connections and GET /admin/connections/user/{email} list ConnectionInfo
// entries: one per account and connection tracker, with snake_case keys. The spec
// described a per-session record with Go field names (ID, ClientAddr, ConnectedAt, ...)
// that no handler ever sent, so a client generated from it read nothing. This pins the
// schema to what json.Marshal emits for the entry type.
func TestOpenAPIConnectionEntriesMatchWireFormat(t *testing.T) {
	for _, tc := range []struct {
		schema string
		entry  any
	}{
		{"ConnectionInfo", ConnectionInfo{}},
	} {
		t.Run(tc.schema, func(t *testing.T) {
			documented := schemaProperties(t, tc.schema)
			wire := wireKeys(t, tc.entry)
			if strings.Join(documented, ",") != strings.Join(wire, ",") {
				t.Fatalf("OpenAPI %s properties do not match the wire format\n  spec: %v\n  wire: %v", tc.schema, documented, wire)
			}
		})
	}
}

// The test above pins the entry types; this one pins what the two handlers write, so a
// key added to a response body or an entry built some other way cannot drift from the
// spec either. Each handler runs with a tracked session and with no trackers (which
// answers note instead of source); the union of the top-level keys must be the 200
// response's properties, and the entry keys the schema the response refers to.
func TestOpenAPIConnectionResponsesMatchHandlers(t *testing.T) {
	tracker := server.NewConnectionTracker("IMAP", "imap", "host", "host-imap", nil, 0, 0, 0, true)
	t.Cleanup(tracker.Stop)
	if err := tracker.RegisterConnection(context.Background(), 123, "user@example.com", "IMAP", "192.0.2.1:50000"); err != nil {
		t.Fatal(err)
	}
	withTracker := &Server{connectionTrackers: func() map[string]*server.ConnectionTracker {
		return map[string]*server.ConnectionTracker{"IMAP-imap": tracker}
	}}
	withoutTrackers := &Server{}

	for _, tc := range []struct {
		path    string
		target  string
		handler func(*Server) http.HandlerFunc
	}{
		{"/connections", "/admin/connections", func(s *Server) http.HandlerFunc { return s.handleListConnections }},
		{"/connections/user/{email}", "/admin/connections/user/user@example.com", func(s *Server) http.HandlerFunc { return s.handleGetUserConnections }},
	} {
		t.Run(tc.path, func(t *testing.T) {
			documented, entrySchema := responseProperties(t, tc.path)

			topLevel := make(map[string]bool)
			var entries []map[string]any
			for _, s := range []*Server{withTracker, withoutTrackers} {
				req := httptest.NewRequest(http.MethodGet, tc.target, nil)
				req.SetPathValue("email", "user@example.com")
				rec := httptest.NewRecorder()
				tc.handler(s)(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("handler answered %d, want 200: %s", rec.Code, rec.Body)
				}
				var body map[string]json.RawMessage
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				for k := range body {
					topLevel[k] = true
				}
				var conns []map[string]any
				if err := json.Unmarshal(body["connections"], &conns); err != nil {
					t.Fatal(err)
				}
				entries = append(entries, conns...)
			}

			var wire []string
			for k := range topLevel {
				wire = append(wire, k)
			}
			sort.Strings(wire)
			if strings.Join(documented, ",") != strings.Join(wire, ",") {
				t.Errorf("OpenAPI %s 200 response properties do not match the handler's response\n  spec: %v\n  wire: %v", tc.path, documented, wire)
			}

			if len(entries) != 1 {
				t.Fatalf("handler listed %d entries for the tracked session, want 1", len(entries))
			}
			var entryKeys []string
			for k := range entries[0] {
				entryKeys = append(entryKeys, k)
			}
			sort.Strings(entryKeys)
			if schema := schemaProperties(t, entrySchema); strings.Join(schema, ",") != strings.Join(entryKeys, ",") {
				t.Errorf("OpenAPI %s properties do not match the entries %s sends\n  spec: %v\n  wire: %v", entrySchema, tc.path, schema, entryKeys)
			}
		})
	}
}

// responseProperties returns the top-level properties of the 200 response of GET path,
// and the schema its connections items refer to.
func responseProperties(t *testing.T, path string) (props []string, itemSchema string) {
	t.Helper()
	spec, err := os.ReadFile("admin_api_openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, op, ok := strings.Cut(string(spec), "\n  "+path+":\n    get:\n")
	if !ok {
		t.Fatalf("GET %s not found in admin_api_openapi.yaml", path)
	}
	if end := regexp.MustCompile(`\n  [^ \n]`).FindStringIndex(op); end != nil {
		op = op[:end[0]]
	}
	_, resp, ok := strings.Cut(op, "\n        '200':\n")
	if !ok {
		t.Fatalf("GET %s has no 200 response in admin_api_openapi.yaml", path)
	}
	if end := regexp.MustCompile(`\n        [^ \n]`).FindStringIndex(resp); end != nil {
		resp = resp[:end[0]]
	}
	for _, m := range regexp.MustCompile(`(?m)^ {18}([A-Za-z_]+):\s*$`).FindAllStringSubmatch(resp, -1) {
		props = append(props, m[1])
	}
	sort.Strings(props)
	m := regexp.MustCompile(`(?m)^ {18}connections:\n(?: {20}.*\n)*? {22}\$ref: '#/components/schemas/([A-Za-z]+)'`).FindStringSubmatch(resp)
	if m == nil {
		t.Fatalf("GET %s: connections items do not refer to a schema", path)
	}
	return props, m[1]
}
