package userapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The spec described five operations differently from their handlers (#689): the
// login and refresh answers with expires_at as a date-time (LoginResponse sends Unix
// seconds) and without email; refresh as a bearer-authenticated call without a body
// (the route is public and handleRefreshToken reads {"token": ...} from the body, so a
// client generated from the spec got 400 "Invalid request body"); a mailbox key in the
// create answer (it is name); a format parameter for /body (none is read); and a
// DELETE answer without the id it sends.

func TestOpenAPITokenEndpointsMatchHandlers(t *testing.T) {
	wire := filledWireShapes[LoginResponse](t)
	for _, path := range []string{"/auth/login", "/auth/refresh"} {
		resp := openAPIResponse(t, path, "post", "200")
		assertShapes(t, "POST "+path+" 200", openAPIBodyShapes(t, path, resp, 14), wire)
	}

	refresh := openAPIOperation(t, "/auth/refresh", "post")
	if _, ok := yamlSection(refresh, 6, "security:"); ok {
		t.Error("POST /auth/refresh requires a security scheme, but the route is public")
	}
	if body, ok := yamlSection(refresh, 6, "requestBody:"); !ok {
		t.Error(`POST /auth/refresh documents no request body, but handleRefreshToken reads {"token": ...}`)
	} else {
		assertShapes(t, "POST /auth/refresh request", openAPIBodyShapes(t, "/auth/refresh", body, 12), filledWireShapes[RefreshTokenRequest](t))
	}

	// The route itself: a refresh without an Authorization header reaches the handler,
	// which reads the token from the body.
	s, err := New(nil, ServerOptions{Name: "openapi", JWTSecret: "openapi-endpoints-test-secret-32-bytes"})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.SetupRoutes().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/user/auth/refresh", strings.NewReader(`{"token":""}`)))
	var answer map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &answer)
	if w.Code != http.StatusBadRequest || answer["error"] != "Token is required" {
		t.Errorf("refresh without Authorization header: %d %q, want 400 Token is required from the handler", w.Code, w.Body.String())
	}
}

// handleCreateMailbox answers {"message", "name"} with the name as created.
func TestOpenAPICreateMailboxResponse(t *testing.T) {
	resp := openAPIResponse(t, "/mailboxes", "post", "201")
	assertShapes(t, "POST /mailboxes 201", openAPIBodyShapes(t, "/mailboxes", resp, 14), []string{"message: string", "name: string"})
}

// handleGetMessageBody reads no query parameter and answers with the message's own
// top-level Content-Type, whatever it is.
func TestOpenAPIMessageBodyOperation(t *testing.T) {
	op := openAPIOperation(t, "/messages/{id}/body", "get")
	params, _ := yamlSection(op, 6, "parameters:")
	var documented []string
	for _, m := range regexp.MustCompile(`(?m)^        - (?:\$ref: '#/components/parameters/|name: )([A-Za-z_]+)`).FindAllStringSubmatch(params, -1) {
		documented = append(documented, m[1])
	}
	if !slices.Equal(documented, []string{"MessageId"}) {
		t.Errorf("GET /messages/{id}/body parameters %v, but handleGetMessageBody reads only the path id", documented)
	}
	content, _ := yamlSection(openAPIResponse(t, "/messages/{id}/body", "get", "200"), 10, "content:")
	if types := yamlKeys(content, 12); !slices.Equal(types, []string{"'*/*'"}) {
		t.Errorf("GET /messages/{id}/body 200 content types %v, want '*/*' (the message's own Content-Type)", types)
	}
}

// handleDeleteMessage only adds \Deleted, answers {"message", "id"}, and refuses with
// 403 in a shared mailbox without the right.
func TestOpenAPIDeleteMessageResponse(t *testing.T) {
	resp := openAPIResponse(t, "/messages/{id}", "delete", "200")
	assertShapes(t, "DELETE /messages/{id} 200", openAPIBodyShapes(t, "/messages/{id}", resp, 14), []string{"id: integer", "message: string"})
	if _, ok := yamlSection(openAPIOperation(t, "/messages/{id}", "delete"), 8, "'403':"); !ok {
		t.Error("DELETE /messages/{id} does not list 403")
	}
}

// handleDeleteMailbox refuses INBOX, and a shared mailbox without the 'x' right, with
// 403 (#992).
func TestOpenAPIDeleteMailboxResponse(t *testing.T) {
	op := openAPIOperation(t, "/mailboxes/{name}", "delete")
	if _, ok := yamlSection(op, 8, "'403':"); !ok {
		t.Error("DELETE /mailboxes/{name} does not list 403")
	}
	if resp, ok := yamlSection(op, 8, "'400':"); ok && strings.Contains(resp, "INBOX") {
		t.Errorf("DELETE /mailboxes/{name} documents the INBOX refusal as 400; it is 403:\n%s", resp)
	}
}

func assertShapes(t *testing.T, what string, documented, wire []string) {
	t.Helper()
	if spec, got := strings.Join(documented, ", "), strings.Join(wire, ", "); spec != got {
		t.Errorf("%s properties do not match the handler\n  spec: %s\n  wire: %s", what, spec, got)
	}
}

// openAPIOperation returns the lines of the method's operation under path in
// user_api_openapi.yaml.
func openAPIOperation(t *testing.T, path, method string) string {
	t.Helper()
	spec, err := os.ReadFile("user_api_openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ops, ok := yamlSection(string(spec), 2, path+":")
	if !ok {
		t.Fatalf("%s not found in user_api_openapi.yaml", path)
	}
	op, ok := yamlSection(ops, 4, method+":")
	if !ok {
		t.Fatalf("%s %s not found in user_api_openapi.yaml", method, path)
	}
	return op
}

// openAPIResponse returns the lines of the operation's response with the status code.
func openAPIResponse(t *testing.T, path, method, code string) string {
	t.Helper()
	resp, ok := yamlSection(openAPIOperation(t, path, method), 8, "'"+code+"':")
	if !ok {
		t.Fatalf("%s %s has no %s response in user_api_openapi.yaml", method, path, code)
	}
	return resp
}

// openAPIBodyShapes returns "name: type" for each property of the JSON schema in
// section (a request body or a response), whose schema: key is indented by indent,
// and nothing when there is no schema. A $ref to a schema is followed.
func openAPIBodyShapes(t *testing.T, what, section string, indent int) []string {
	t.Helper()
	schema, ok := yamlSection(section, indent, "schema:")
	if !ok {
		return nil
	}
	ref := regexp.MustCompile(fmt.Sprintf(`(?m)^ {%d}\$ref: '#/components/schemas/([A-Za-z]+)'$`, indent+2))
	if m := ref.FindStringSubmatch(schema); m != nil {
		return openAPIPropertyShapes(t, m[1])
	}
	props, ok := yamlSection(schema, indent+2, "properties:")
	if !ok {
		t.Fatalf("%s: schema without properties", what)
	}
	return propertyShapes(t, props, indent+4)
}

// yamlSection returns the lines under the line holding key at the given indentation,
// up to the next line indented as much or less.
func yamlSection(block string, indent int, key string) (string, bool) {
	_, section, ok := strings.Cut("\n"+block, "\n"+strings.Repeat(" ", indent)+key+"\n")
	if !ok {
		return "", false
	}
	if end := regexp.MustCompile(fmt.Sprintf(`(?m)^ {0,%d}[^ \n]`, indent)).FindStringIndex(section); end != nil {
		section = section[:end[0]]
	}
	return section, true
}

// yamlKeys returns the keys in block at the given indentation, in order.
func yamlKeys(block string, indent int) []string {
	var keys []string
	for _, m := range regexp.MustCompile(fmt.Sprintf(`(?m)^ {%d}([^ \n][^:\n]*):`, indent)).FindAllStringSubmatch(block, -1) {
		keys = append(keys, m[1])
	}
	return keys
}
