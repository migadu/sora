package adminapi

import (
	"encoding/json"
	"fmt"
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

// openAPIResponseBlocks returns the YAML of each response op documents, by status code.
// A response that refers to a components/responses entry is that entry, indented as if
// it were written in the operation.
func openAPIResponseBlocks(t *testing.T, op string) map[string]string {
	t.Helper()
	responses := section(op, "responses", 6)
	codes := regexp.MustCompile(`(?m)^ {8}'(\d{3})':\s*$`).FindAllStringSubmatchIndex(responses, -1)
	blocks := make(map[string]string)
	for i, m := range codes {
		end := len(responses)
		if i+1 < len(codes) {
			end = codes[i+1][0]
		}
		body := responses[m[1]:end]
		if ref := regexp.MustCompile(`^\n {10}\$ref: '#/components/responses/([A-Za-z]+)'`).FindStringSubmatch(body); ref != nil {
			body = componentResponse(t, ref[1])
		}
		blocks[responses[m[2]:m[3]]] = body
	}
	return blocks
}

// componentResponse returns the YAML of a components/responses entry, indented as a
// response written in an operation.
func componentResponse(t *testing.T, name string) string {
	t.Helper()
	spec, err := os.ReadFile("admin_api_openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, components, ok := strings.Cut(string(spec), "\ncomponents:\n")
	if !ok {
		t.Fatal("components section not found in admin_api_openapi.yaml")
	}
	block := section(section(components, "responses", 2), name, 4)
	if block == "" {
		t.Fatalf("%s response not found in admin_api_openapi.yaml components", name)
	}
	return "\n" + regexp.MustCompile(`(?m)^`).ReplaceAllString(block, "    ")
}

// openAPIResponses returns the status codes op documents, each with the top-level
// properties of its JSON body: the inline schema's, or the referenced component's.
func openAPIResponses(t *testing.T, op string) map[string][]string {
	t.Helper()
	documented := make(map[string][]string)
	for code, body := range openAPIResponseBlocks(t, op) {
		var props []string
		if ref := regexp.MustCompile(`\n {14}schema:\n {16}\$ref: '#/components/schemas/([A-Za-z]+)'`).FindStringSubmatch(body); ref != nil {
			props = schemaProperties(t, ref[1])
		} else {
			for _, p := range regexp.MustCompile(`(?m)^ {18}([A-Za-z_]+):\s*$`).FindAllStringSubmatch(section(body, "properties", 16), -1) {
				props = append(props, p[1])
			}
			sort.Strings(props)
		}
		documented[code] = props
	}
	return documented
}

// openAPIQueryParameters returns the names of op's query parameters.
func openAPIQueryParameters(op string) []string {
	var names []string
	for _, m := range regexp.MustCompile(`\n {8}- name: ([A-Za-z_]+)\n {10}in: query\n`).FindAllStringSubmatch("\n"+section(op, "parameters", 6), -1) {
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

// writeCalls calls visit with each s.writeJSON and s.writeError call in the handlers and
// the status it writes, a net/http status constant.
func writeCalls(t *testing.T, handlers []*ast.FuncDecl, visit func(fn *ast.FuncDecl, call *ast.CallExpr, code int)) {
	t.Helper()
	statusCodes := make(map[string]int)
	for code := 100; code < 600; code++ {
		if text := http.StatusText(code); text != "" {
			statusCodes["Status"+strings.NewReplacer(" ", "", "-", "").Replace(text)] = code
		}
	}
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
			visit(fn, call, code)
			return true
		})
	}
}

// mapLiteralKeys returns the keys of a map literal, which must be string literals.
func mapLiteralKeys(t *testing.T, fn *ast.FuncDecl, e ast.Expr) ([]string, bool) {
	t.Helper()
	lit, ok := e.(*ast.CompositeLit)
	if ok {
		_, ok = lit.Type.(*ast.MapType)
	}
	if !ok {
		return nil, false
	}
	var keys []string
	for _, elt := range lit.Elts {
		key, ok := stringLiteral(elt.(*ast.KeyValueExpr).Key)
		if !ok {
			t.Fatalf("%s: writeJSON body has a key that is not a string literal", fn.Name.Name)
		}
		keys = append(keys, key)
	}
	return keys, true
}

// mapVariableKeys returns the keys a map variable of fn is given: those of the map
// literal it is declared with (name := map[...]...{...}) and those it is assigned
// (name["key"] = ...).
func mapVariableKeys(t *testing.T, fn *ast.FuncDecl, name string) []string {
	t.Helper()
	var keys []string
	declared := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		switch lhs := assign.Lhs[0].(type) {
		case *ast.Ident:
			if lhs.Name == name && assign.Tok == token.DEFINE {
				lit, ok := mapLiteralKeys(t, fn, assign.Rhs[0])
				if !ok {
					t.Fatalf("%s: writeJSON body %s is not declared with a map literal; teach this test", fn.Name.Name, name)
				}
				keys = append(keys, lit...)
				declared = true
			}
		case *ast.IndexExpr:
			if ident, ok := lhs.X.(*ast.Ident); ok && ident.Name == name {
				key, ok := stringLiteral(lhs.Index)
				if !ok {
					t.Fatalf("%s: writeJSON body %s is given a key that is not a string literal", fn.Name.Name, name)
				}
				keys = append(keys, key)
			}
		}
		return true
	})
	if !declared {
		t.Fatalf("%s: writeJSON body %s is not declared in the handler; teach this test", fn.Name.Name, name)
	}
	return keys
}

// handlerResponses returns each status the handlers answer with s.writeJSON or
// s.writeError, with the top-level keys its bodies can carry: "error" for writeError,
// the keys of the map literal for writeJSON, or of the map variable it is built in.
func handlerResponses(t *testing.T, handlers ...*ast.FuncDecl) map[string][]string {
	t.Helper()
	written := make(map[string][]string)
	writeCalls(t, handlers, func(fn *ast.FuncDecl, call *ast.CallExpr, code int) {
		keys := []string{"error"}
		if call.Fun.(*ast.SelectorExpr).Sel.Name == "writeJSON" {
			var ok bool
			if keys, ok = mapLiteralKeys(t, fn, call.Args[2]); !ok {
				ident, isIdent := call.Args[2].(*ast.Ident)
				if !isIdent {
					t.Fatalf("%s: writeJSON body is not a map literal or variable; teach this test", fn.Name.Name)
				}
				keys = mapVariableKeys(t, fn, ident.Name)
			}
		}
		c := strconv.Itoa(code)
		for _, key := range keys {
			if !slices.Contains(written[c], key) {
				written[c] = append(written[c], key)
			}
		}
		sort.Strings(written[c])
	})
	return written
}

// handlerErrors returns the messages the handlers answer with s.writeError, by status.
// Messages that are not string literals are left out.
func handlerErrors(t *testing.T, handlers ...*ast.FuncDecl) map[string][]string {
	t.Helper()
	messages := make(map[string][]string)
	writeCalls(t, handlers, func(fn *ast.FuncDecl, call *ast.CallExpr, code int) {
		if call.Fun.(*ast.SelectorExpr).Sel.Name != "writeError" {
			return
		}
		if msg, ok := stringLiteral(call.Args[2]); ok {
			messages[strconv.Itoa(code)] = append(messages[strconv.Itoa(code)], msg)
		}
	})
	return messages
}

// accessMiddleware returns the middleware every request passes before the router looks
// at its path: the allowed_hosts check and the API key check.
func accessMiddleware(t *testing.T) []*ast.FuncDecl {
	t.Helper()
	return []*ast.FuncDecl{handlerFunc(t, "allowedHostsMiddleware"), handlerFunc(t, "authMiddleware")}
}

// handlerQueryParameters returns the query parameters the handlers read with
// r.URL.Query().Get, or with Get on a variable holding r.URL.Query().
func handlerQueryParameters(handlers ...*ast.FuncDecl) []string {
	isQuery := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "Query"
	}
	var names []string
	for _, fn := range handlers {
		queries := make(map[string]bool)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if assign, ok := n.(*ast.AssignStmt); ok && len(assign.Lhs) == 1 && len(assign.Rhs) == 1 && isQuery(assign.Rhs[0]) {
				if ident, ok := assign.Lhs[0].(*ast.Ident); ok {
					queries[ident.Name] = true
				}
			}
			return true
		})
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			get, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || get.Sel.Name != "Get" {
				return true
			}
			if ident, ok := get.X.(*ast.Ident); !isQuery(get.X) && (!ok || !queries[ident.Name]) {
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
// wire format is pinned to the handler's source: the status codes it and the access
// middleware answer with and the keys each body can carry must be what the spec
// documents, the query parameters it reads must be the operation's, and the request
// fields it reads the request schema's. The spec had documented keys no handler sent
// (connections_marked, email), left out keys the handlers send (instance_id, since,
// max_attempts, limit, email) and statuses they answer (400, 404, 409, 500, 503),
// described request filters the kick ignores (server_addr, client_addr, all), and had
// no purge=true mode at all.
func TestOpenAPIOperationsMatchHandlers(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		handlers     []string
		request      any
	}{
		{"POST", "/connections/kick", []string{"handleKickConnections"}, KickConnectionsRequest{}},
		{"POST", "/accounts/{email}/credentials", []string{"handleAddCredential"}, AddCredentialRequest{}},
		{"DELETE", "/accounts/{email}", []string{"handleDeleteAccount", "handlePurgeAccount"}, nil},
		{"POST", "/accounts/{email}/messages/restore", []string{"handleRestoreMessages"}, nil},
		{"DELETE", "/credentials/{email}", []string{"handleDeleteCredential"}, nil},
		{"GET", "/usage/accounts", []string{"handleAccountUsage"}, nil},
		{"GET", "/cache/metrics", []string{"handleCacheMetrics"}, nil},
		{"GET", "/uploader/status", []string{"handleUploaderStatus"}, nil},
		{"GET", "/uploader/failed", []string{"handleFailedUploads"}, nil},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			op := openAPIOperation(t, tc.method, tc.path)
			var fns []*ast.FuncDecl
			for _, name := range tc.handlers {
				fns = append(fns, handlerFunc(t, name))
			}

			documented := openAPIResponses(t, op)
			written := handlerResponses(t, append(accessMiddleware(t), fns...)...)
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

// Every request passes allowedHostsMiddleware and authMiddleware before the router looks
// at its path, so every operation can be refused by them. The spec described a wrong key
// as 401 "invalid or missing API key" on four operations and documented 403 on none,
// while the server answers 401 only for a missing or non-Bearer Authorization header,
// and 403 for a wrong key, the read-only key on a write, or a client outside
// allowed_hosts. This pins every operation to the statuses and messages the middleware
// answers with.
func TestOpenAPIDocumentsAccessRefusalsOnEveryOperation(t *testing.T) {
	middleware := accessMiddleware(t)
	refusals := handlerResponses(t, middleware...)
	messages := handlerErrors(t, middleware...)
	if len(refusals) == 0 {
		t.Fatal("found no responses in the access middleware")
	}
	var problems []string
	for path, methods := range openAPIOperations(t) {
		for _, method := range methods {
			op := openAPIOperation(t, method, path)
			documented := openAPIResponses(t, op)
			blocks := openAPIResponseBlocks(t, op)
			for code, keys := range refusals {
				if spec, ok := documented[code]; !ok {
					problems = append(problems, fmt.Sprintf("%s %s does not document %s", method, path, code))
					continue
				} else if !slices.Equal(spec, keys) {
					problems = append(problems, fmt.Sprintf("%s %s documents %s with %v, the middleware answers %v", method, path, code, spec, keys))
				}
				for _, msg := range messages[code] {
					if !strings.Contains(blocks[code], msg) {
						problems = append(problems, fmt.Sprintf("%s %s: %s does not mention %q", method, path, code, msg))
					}
				}
			}
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		t.Fatalf("operations that do not document the access middleware's refusals:\n  %s", strings.Join(problems, "\n  "))
	}
}

// The uploader endpoints' max_attempts defaults to the node's [uploader] max_attempts
// (config.DefaultUploaderMaxAttempts unless configured), the attempt count at which the
// uploader stops retrying. The spec documented a fixed default of 5, so a client that
// sent the documented default listed as failed the uploads still being retried.
func TestOpenAPIUploaderMaxAttemptsDefault(t *testing.T) {
	for _, path := range []string{"/uploader/status", "/uploader/failed"} {
		_, param, ok := strings.Cut(section(openAPIOperation(t, "GET", path), "parameters", 6), "- name: max_attempts\n")
		if !ok {
			t.Fatalf("GET %s does not document max_attempts", path)
		}
		param, _, _ = strings.Cut(param, "- name: ")
		if strings.Contains(param, "default:") {
			t.Errorf("GET %s documents a fixed max_attempts default; the server applies [uploader] max_attempts:\n%s", path, param)
		}
		if !strings.Contains(param, "[uploader] max_attempts") {
			t.Errorf("GET %s max_attempts does not say it defaults to [uploader] max_attempts:\n%s", path, param)
		}
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
