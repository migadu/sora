package adminapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// GET /health/servers/{hostname}/components/{component} answers the current status only:
// health_status keeps one row per component and server, rewritten in place, so there is
// no history, and history=true is refused with 400. The spec kept describing history,
// since and limit parameters and a history response after the handler stopped serving
// them, so a client generated from it asked for a history and got an undocumented 400.
func TestOpenAPIHealthComponentDescribesNoHistory(t *testing.T) {
	const path = "/health/servers/{hostname}/components/{component}"
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

	for _, param := range []string{"history", "since", "limit"} {
		if regexp.MustCompile(`\n\s+- name: ` + param + `\n`).MatchString(op) {
			t.Errorf("GET %s documents the %q parameter, but the handler keeps no history", path, param)
		}
	}
	if regexp.MustCompile(`\n\s+history:\s*\n`).MatchString(op) {
		t.Errorf("GET %s documents a history response, but the handler only returns the current status", path)
	}
	if !strings.Contains(op, "\n        '400':\n") {
		t.Errorf("GET %s does not document the 400 answered to history=true", path)
	}

	rec := httptest.NewRecorder()
	(&Server{}).handleHealthStatusByComponent(rec, httptest.NewRequest(http.MethodGet,
		"/admin/health/servers/mail-server-01/components/database?history=true", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("history=true answered %d, want 400", rec.Code)
	}
}
