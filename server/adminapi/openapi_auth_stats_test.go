package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// GET /auth/stats answers a fixed description of the in-memory rate limiting and reads
// no query parameters. The spec kept describing attempt counters for a window (stats,
// window, window_seconds) long after the handler stopped returning them, so a client
// written against it read nothing. This pins the documented 200 response to the keys the
// handler writes, and the operation to no parameters.
func TestOpenAPIAuthStatsMatchesResponse(t *testing.T) {
	spec, err := os.ReadFile("admin_api_openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, op, ok := strings.Cut(string(spec), "\n  /auth/stats:\n")
	if !ok {
		t.Fatal("/auth/stats not found in admin_api_openapi.yaml")
	}
	if end := regexp.MustCompile(`\n  [^ \n]`).FindStringIndex(op); end != nil {
		op = op[:end[0]]
	}

	if strings.Contains(op, "\n      parameters:\n") {
		t.Error("/auth/stats documents parameters, but handleAuthStats reads none")
	}

	_, resp, ok := strings.Cut(op, "\n        '200':\n")
	if !ok {
		t.Fatal("/auth/stats has no 200 response in admin_api_openapi.yaml")
	}
	if end := regexp.MustCompile(`\n        [^ \n]`).FindStringIndex(resp); end != nil {
		resp = resp[:end[0]]
	}
	var documented []string
	for _, m := range regexp.MustCompile(`(?m)^ {18}([A-Za-z_]+):\s*$`).FindAllStringSubmatch(resp, -1) {
		documented = append(documented, m[1])
	}

	rec := httptest.NewRecorder()
	(&Server{}).handleAuthStats(rec, httptest.NewRequest(http.MethodGet, "/admin/auth/stats?window=1h", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("handleAuthStats answered %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var wire []string
	for k := range body {
		wire = append(wire, k)
	}

	sort.Strings(documented)
	sort.Strings(wire)
	if strings.Join(documented, ",") != strings.Join(wire, ",") {
		t.Fatalf("OpenAPI /auth/stats 200 response properties do not match the handler's response\n  spec: %v\n  wire: %v", documented, wire)
	}
}
