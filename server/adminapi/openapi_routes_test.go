package adminapi

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
)

// registeredRoutes returns the exact routes setupRoutes registers (as the spec writes
// them, without the /admin server prefix) with the methods each accepts. Prefix routes
// ("/admin/accounts/") dispatch to sub-handlers that match the rest of the path in code,
// so only exact routes are listed.
func registeredRoutes(t *testing.T) map[string][]string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	unquote := func(e ast.Expr) string {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			t.Fatalf("expected a string literal, got %T", e)
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	routes := make(map[string][]string)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "setupRoutes" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "HandleFunc" {
				return true
			}
			path := unquote(call.Args[0])
			if strings.HasSuffix(path, "/") {
				return false
			}
			path = strings.TrimPrefix(path, "/admin")
			wrapper, ok := call.Args[1].(*ast.CallExpr)
			if !ok {
				t.Fatalf("%s: handler is not wrapped in routeHandler/multiMethodHandler; teach this test its methods", path)
			}
			switch ident, _ := wrapper.Fun.(*ast.Ident); {
			case ident != nil && ident.Name == "routeHandler":
				routes[path] = append(routes[path], unquote(wrapper.Args[0]))
			case ident != nil && ident.Name == "multiMethodHandler":
				for _, elt := range wrapper.Args[0].(*ast.CompositeLit).Elts {
					routes[path] = append(routes[path], unquote(elt.(*ast.KeyValueExpr).Key))
				}
			default:
				t.Fatalf("%s: unknown handler wrapper; teach this test its methods", path)
			}
			return false
		})
	}
	if len(routes) == 0 {
		t.Fatal("no routes found in setupRoutes")
	}
	return routes
}

// openAPIOperations returns the spec's paths with the methods described under each.
func openAPIOperations(t *testing.T) map[string][]string {
	t.Helper()
	spec, err := os.ReadFile("admin_api_openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, paths, ok := strings.Cut(string(spec), "\npaths:\n")
	if !ok {
		t.Fatal("paths section not found in admin_api_openapi.yaml")
	}
	pathRe := regexp.MustCompile(`^  (/\S*):\s*$`)
	methodRe := regexp.MustCompile(`^    (get|put|post|delete|patch|head|options):\s*$`)
	ops := make(map[string][]string)
	var current string
	for _, line := range strings.Split(paths, "\n") {
		if m := pathRe.FindStringSubmatch(line); m != nil {
			current = m[1]
			ops[current] = nil
		} else if m := methodRe.FindStringSubmatch(line); m != nil && current != "" {
			ops[current] = append(ops[current], strings.ToUpper(m[1]))
		}
	}
	return ops
}

// A route the server answers but the spec does not describe cannot be called by a client
// generated from the spec. This pins every exact route and method in setupRoutes to an
// operation in admin_api_openapi.yaml.
func TestOpenAPIDescribesEveryRegisteredRoute(t *testing.T) {
	documented := openAPIOperations(t)
	var missing []string
	for path, methods := range registeredRoutes(t) {
		for _, method := range methods {
			if !slices.Contains(documented[path], method) {
				missing = append(missing, method+" /admin"+path)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("routes registered in setupRoutes but not described in admin_api_openapi.yaml:\n  %s", strings.Join(missing, "\n  "))
	}
}

// The prefix routes (/admin/accounts/, /admin/credentials/, ...) pick the handler from
// the rest of the path and the method in code, so the test above cannot see them. This
// asks the router instead: on every path the spec describes, a method the spec does not
// list must be refused with 405. The server has no database, so a request that reaches a
// handler usually panics; that, like any status but 405, means the method is served.
func TestOpenAPIDescribesEveryServedMethod(t *testing.T) {
	const key = "openapi-test-api-key-aaaaaaaaaaaaaaaa"
	s := &Server{}
	s.settings.Store(&reloadableSettings{apiKey: key})
	handler := s.setupRoutes()

	served := func(method, target string) (result string) {
		defer func() {
			if r := recover(); r != nil {
				result = "reached a handler"
			}
		}()
		req := httptest.NewRequest(method, target, nil)
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusMethodNotAllowed {
			return ""
		}
		return "status " + strconv.Itoa(rec.Code)
	}

	param := regexp.MustCompile(`\{[^}]+\}`)
	var undocumented []string
	for path, methods := range openAPIOperations(t) {
		target := "/admin" + param.ReplaceAllString(path, "user@example.com")
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			if slices.Contains(methods, method) {
				continue
			}
			if result := served(method, target); result != "" {
				undocumented = append(undocumented, method+" /admin"+path+" ("+result+")")
			}
		}
	}
	sort.Strings(undocumented)
	if len(undocumented) > 0 {
		t.Fatalf("methods the server serves on a described path but admin_api_openapi.yaml does not list:\n  %s", strings.Join(undocumented, "\n  "))
	}
}

// schemaProperties returns the top-level property names of a components/schemas entry.
func schemaProperties(t *testing.T, name string) []string {
	t.Helper()
	spec, err := os.ReadFile("admin_api_openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	header := "    " + name + ":"
	start := strings.Index(string(spec), "\n"+header+"\n")
	if start < 0 {
		t.Fatalf("%s schema not found in admin_api_openapi.yaml", name)
	}
	block := string(spec)[start+1:]
	if end := regexp.MustCompile(`\n    [A-Za-z]`).FindStringIndex(block[len(header):]); end != nil {
		block = block[:len(header)+end[0]]
	}
	var props []string
	for _, m := range regexp.MustCompile(`(?m)^        ([A-Za-z_]+):\s*$`).FindAllStringSubmatch(block, -1) {
		props = append(props, m[1])
	}
	sort.Strings(props)
	return props
}

// wireKeys returns the JSON object keys json.Marshal emits for v.
func wireKeys(t *testing.T, v any) []string {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// GET /cache/stats and the stats_before/stats_after of POST /cache/purge encode
// cache.CacheStats directly; the struct has no JSON tags, so the wire keys are its Go
// field names. The spec must name those keys.
func TestOpenAPICacheStatsMatchesWireFormat(t *testing.T) {
	documented := schemaProperties(t, "CacheStats")
	wire := wireKeys(t, cache.CacheStats{})
	if strings.Join(documented, ",") != strings.Join(wire, ",") {
		t.Fatalf("OpenAPI CacheStats properties do not match the wire format\n  spec: %v\n  wire: %v", documented, wire)
	}
}

// GET /accounts/{email}/credentials lists db.Credential values; the struct has no JSON
// tags either, so the spec must name its Go field names.
func TestOpenAPIAccountCredentialMatchesWireFormat(t *testing.T) {
	documented := schemaProperties(t, "AccountCredential")
	wire := wireKeys(t, db.Credential{})
	if strings.Join(documented, ",") != strings.Join(wire, ",") {
		t.Fatalf("OpenAPI AccountCredential properties do not match the wire format\n  spec: %v\n  wire: %v", documented, wire)
	}
}
