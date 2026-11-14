package adminapi

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
)

// openAPIOperation returns the YAML of the method's operation on path.
func openAPIOperation(t *testing.T, method, path string) string {
	t.Helper()
	spec, err := os.ReadFile("admin_api_openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, block, ok := strings.Cut(string(spec), "\n  "+path+":\n")
	if !ok {
		t.Fatalf("%s not found in admin_api_openapi.yaml", path)
	}
	if end := regexp.MustCompile(`\n  [^ \n]`).FindStringIndex(block); end != nil {
		block = block[:end[0]]
	}
	_, op, ok := strings.Cut("\n"+block, "\n    "+strings.ToLower(method)+":\n")
	if !ok {
		t.Fatalf("%s %s not found in admin_api_openapi.yaml", method, path)
	}
	if end := regexp.MustCompile(`\n    [^ \n]`).FindStringIndex(op); end != nil {
		op = op[:end[0]]
	}
	return op
}

// section returns the lines of op under the key at the given indentation, up to the next
// key at that indentation or less.
func section(op, key string, indent int) string {
	pad := strings.Repeat(" ", indent)
	_, s, ok := strings.Cut("\n"+op, "\n"+pad+key+":\n")
	if !ok {
		return ""
	}
	if end := regexp.MustCompile(`\n {0,` + strconv.Itoa(indent) + `}[^ \n]`).FindStringIndex(s); end != nil {
		s = s[:end[0]]
	}
	return s
}

// openAPIResponses returns the status codes op documents, each with the top-level
// properties of its JSON body: the inline schema's, or the referenced component's.
func openAPIResponses(t *testing.T, op string) map[string][]string {
	t.Helper()
	responses := section(op, "responses", 6)
	codes := regexp.MustCompile(`(?m)^ {8}'(\d{3})':\s*$`).FindAllStringSubmatchIndex(responses, -1)
	documented := make(map[string][]string)
	for i, m := range codes {
		end := len(responses)
		if i+1 < len(codes) {
			end = codes[i+1][0]
		}
		body := responses[m[1]:end]
		var props []string
		if ref := regexp.MustCompile(`\n {14}schema:\n {16}\$ref: '#/components/schemas/([A-Za-z]+)'`).FindStringSubmatch(body); ref != nil {
			props = schemaProperties(t, ref[1])
		} else {
			for _, p := range regexp.MustCompile(`(?m)^ {18}([A-Za-z_]+):\s*$`).FindAllStringSubmatch(section(body, "properties", 16), -1) {
				props = append(props, p[1])
			}
			sort.Strings(props)
		}
		documented[responses[m[2]:m[3]]] = props
	}
	return documented
}

// openAPIQueryParameters returns the names of op's query parameters.
func openAPIQueryParameters(op string) []string {
	var names []string
	for _, m := range regexp.MustCompile(`\n {8}- name: ([A-Za-z_]+)\n {10}in: query\n`).FindAllStringSubmatch(section(op, "parameters", 6), -1) {
		names = append(names, m[1])
	}
	sort.Strings(names)
	return names
}

// handlerFunc returns the declaration of the Server method name in this package.
func handlerFunc(t *testing.T, name string) *ast.FuncDecl {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Name.Name == name {
				return fn
			}
		}
	}
	t.Fatalf("handler %s not found", name)
	return nil
}

// stringLiteral returns the value of a string literal, and false for anything else.
func stringLiteral(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// handlerResponses returns each status the handlers answer with s.writeJSON or
// s.writeError, with the top-level keys of that body: "error" for writeError, the keys
// of the map literal for writeJSON.
func handlerResponses(t *testing.T, handlers ...*ast.FuncDecl) map[string][]string {
	t.Helper()
	statusCodes := make(map[string]int)
	for code := 100; code < 600; code++ {
		if text := http.StatusText(code); text != "" {
			statusCodes["Status"+strings.NewReplacer(" ", "", "-", "").Replace(text)] = code
		}
	}

	written := make(map[string][]string)
	for _, fn := range handlers {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "writeJSON" && sel.Sel.Name != "writeError") {
				return true
			}
			var code int
			if status, ok := call.Args[1].(*ast.SelectorExpr); ok {
				code = statusCodes[status.Sel.Name]
			}
			if code == 0 {
				t.Fatalf("%s: status argument %#v is not a net/http status constant; teach this test", fn.Name.Name, call.Args[1])
			}
			keys := []string{"error"}
			if sel.Sel.Name == "writeJSON" {
				body, ok := call.Args[2].(*ast.CompositeLit)
				if ok {
					_, ok = body.Type.(*ast.MapType)
				}
				if !ok {
					t.Fatalf("%s: writeJSON body is not a map literal; teach this test", fn.Name.Name)
				}
				keys = nil
				for _, elt := range body.Elts {
					key, ok := stringLiteral(elt.(*ast.KeyValueExpr).Key)
					if !ok {
						t.Fatalf("%s: writeJSON body has a key that is not a string literal", fn.Name.Name)
					}
					keys = append(keys, key)
				}
				sort.Strings(keys)
			}
			c := strconv.Itoa(code)
			if prev, seen := written[c]; seen && !slices.Equal(prev, keys) {
				t.Fatalf("%s: status %s is written with keys %v and %v", fn.Name.Name, c, prev, keys)
			}
			written[c] = keys
			return true
		})
	}
	return written
}

// handlerQueryParameters returns the query parameters the handlers read with
// r.URL.Query().Get.
func handlerQueryParameters(handlers ...*ast.FuncDecl) []string {
	var names []string
	for _, fn := range handlers {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			get, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || get.Sel.Name != "Get" {
				return true
			}
			query, ok := get.X.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := query.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Query" {
				return true
			}
			if name, ok := stringLiteral(call.Args[0]); ok && !slices.Contains(names, name) {
				names = append(names, name)
			}
			return true
		})
	}
	sort.Strings(names)
	return names
}

// handlerRequestFields returns the JSON names of the fields of the request struct the
// handler reads (as req.Field).
func handlerRequestFields(t *testing.T, fn *ast.FuncDecl, request any) []string {
	t.Helper()
	typ := reflect.TypeOf(request)
	var names []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); !ok || ident.Name != "req" {
			return true
		}
		field, ok := typ.FieldByName(sel.Sel.Name)
		if !ok {
			t.Fatalf("%s reads req.%s, which %s does not have", fn.Name.Name, sel.Sel.Name, typ)
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
		return true
	})
	sort.Strings(names)
	return names
}

// These operations answer JSON objects built in the handler, not typed structs, so the
// wire format is pinned to the handler's source: the status codes it answers with and
// the keys of each body must be what the spec documents, the query parameters it reads
// must be the operation's, and the request fields it reads the request schema's. The
// spec had documented keys no handler sent (connections_marked, email), left out
// statuses the handlers answer (404, 409, 503), described request filters the kick
// ignores (server_addr, client_addr, all), and had no purge=true mode at all.
func TestOpenAPIOperationsMatchHandlers(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		handlers     []string
		request      any
	}{
		{"POST", "/connections/kick", []string{"handleKickConnections"}, KickConnectionsRequest{}},
		{"POST", "/accounts/{email}/credentials", []string{"handleAddCredential"}, AddCredentialRequest{}},
		{"DELETE", "/accounts/{email}", []string{"handleDeleteAccount", "handlePurgeAccount"}, nil},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			op := openAPIOperation(t, tc.method, tc.path)
			var fns []*ast.FuncDecl
			for _, name := range tc.handlers {
				fns = append(fns, handlerFunc(t, name))
			}

			documented := openAPIResponses(t, op)
			written := handlerResponses(t, fns...)
			var codes []string
			for code := range written {
				codes = append(codes, code)
			}
			for code := range documented {
				if _, ok := written[code]; !ok {
					codes = append(codes, code)
				}
			}
			sort.Strings(codes)
			for _, code := range codes {
				spec, inSpec := documented[code]
				wire, inWire := written[code]
				switch {
				case !inSpec:
					t.Errorf("%s answers %s %v, which the spec does not document", strings.Join(tc.handlers, "/"), code, wire)
				case !inWire:
					t.Errorf("the spec documents %s %v, which %s never answers", code, spec, strings.Join(tc.handlers, "/"))
				case !slices.Equal(spec, wire):
					t.Errorf("%s response properties do not match the handler's body\n  spec: %v\n  wire: %v", code, spec, wire)
				}
			}

			if spec, wire := openAPIQueryParameters(op), handlerQueryParameters(fns...); !slices.Equal(spec, wire) {
				t.Errorf("query parameters do not match what the handler reads\n  spec: %v\n  read: %v", spec, wire)
			}

			if tc.request != nil {
				ref := regexp.MustCompile(`\$ref: '#/components/schemas/([A-Za-z]+)'`).FindStringSubmatch(section(op, "requestBody", 6))
				if ref == nil {
					t.Fatal("the request body does not refer to a schema")
				}
				if spec, read := schemaProperties(t, ref[1]), handlerRequestFields(t, fns[0], tc.request); !slices.Equal(spec, read) {
					t.Errorf("%s properties do not match the request fields the handler reads\n  spec: %v\n  read: %v", ref[1], spec, read)
				}
			}
		})
	}
}

// GET /accounts/{email} encodes db.AccountDetails. Its pointer fields are omitted while
// unset, so they are set here: purge_requested_at is sent while a purge is pending.
func TestOpenAPIAccountMatchesWireFormat(t *testing.T) {
	now := time.Now()
	documented := schemaProperties(t, "Account")
	wire := wireKeys(t, db.AccountDetails{DeletedAt: &now, PurgeRequestedAt: &now})
	if !slices.Equal(documented, wire) {
		t.Fatalf("OpenAPI Account properties do not match the wire format\n  spec: %v\n  wire: %v", documented, wire)
	}
}

// GET /config lists the API's endpoints. The list is written by hand, so this pins it to
// the operations the spec describes (which the tests in openapi_routes_test.go pin to the
// router), and the response's keys to the spec's.
func TestOpenAPIConfigListsEveryOperation(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Server{}).handleConfigInfo(rec, httptest.NewRequest(http.MethodGet, "/admin/config", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("handleConfigInfo answered %d, want 200", rec.Code)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	var keys []string
	for k := range body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if documented := openAPIResponses(t, openAPIOperation(t, "GET", "/config"))["200"]; !slices.Equal(documented, keys) {
		t.Errorf("OpenAPI /config 200 response properties do not match the handler's response\n  spec: %v\n  wire: %v", documented, keys)
	}

	var endpoints map[string][]string
	if err := json.Unmarshal(body["endpoints"], &endpoints); err != nil {
		t.Fatal(err)
	}
	listed := make(map[string]bool)
	for _, group := range endpoints {
		for _, entry := range group {
			// "METHOD /admin/path?query (note)"
			fields := strings.Fields(entry)
			if len(fields) < 2 || !strings.HasPrefix(fields[1], "/admin/") {
				t.Fatalf("endpoint %q is not \"METHOD /admin/path ...\"", entry)
			}
			path, _, _ := strings.Cut(strings.TrimPrefix(fields[1], "/admin"), "?")
			listed[fields[0]+" "+path] = true
		}
	}
	var described []string
	for path, methods := range openAPIOperations(t) {
		for _, method := range methods {
			described = append(described, method+" "+path)
		}
	}
	sort.Strings(described)

	var missing, extra []string
	for _, op := range described {
		if !listed[op] {
			missing = append(missing, op)
		}
	}
	for op := range listed {
		if !slices.Contains(described, op) {
			extra = append(extra, op)
		}
	}
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("operations the spec describes but GET /config does not list:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(extra) > 0 {
		t.Errorf("endpoints GET /config lists but the spec does not describe:\n  %s", strings.Join(extra, "\n  "))
	}
}
