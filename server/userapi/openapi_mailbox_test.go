package userapi

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// GET /user/mailboxes encodes MailboxInfo directly. The OpenAPI Mailbox schema named
// total_messages, unseen_messages, uidvalidity and uidnext, none of which the server
// sends (#414). This pins the schema to what json.Marshal emits, so the two cannot drift.
func TestOpenAPIMailboxMatchesWireFormat(t *testing.T) {
	documented := openAPISchemaProperties(t, "Mailbox")
	wire := jsonWireKeys(t, MailboxInfo{})
	if strings.Join(documented, ",") != strings.Join(wire, ",") {
		t.Fatalf("OpenAPI Mailbox properties do not match the wire format\n  spec: %v\n  wire: %v", documented, wire)
	}
}

// openAPISchemaProperties returns the sorted property names of the named schema in
// user_api_openapi.yaml.
func openAPISchemaProperties(t *testing.T, name string) []string {
	t.Helper()
	var props []string
	for _, m := range openAPIPropertyName.FindAllStringSubmatch(openAPISchemaBlock(t, name), -1) {
		props = append(props, m[1])
	}
	sort.Strings(props)
	return props
}

// openAPIPropertyName matches the line naming a property of a schema.
var openAPIPropertyName = regexp.MustCompile(`(?m)^        ([A-Za-z_]+):\s*$`)

// openAPISchemaBlock returns the named schema in user_api_openapi.yaml, from its
// "    Name:" line up to the next schema.
func openAPISchemaBlock(t *testing.T, name string) string {
	t.Helper()
	spec, err := os.ReadFile("user_api_openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	header := "    " + name + ":"
	start := strings.Index(string(spec), "\n"+header+"\n")
	if start < 0 {
		t.Fatalf("%s schema not found in user_api_openapi.yaml", name)
	}
	block := string(spec)[start+1:]
	if end := regexp.MustCompile(`\n    [A-Za-z]`).FindStringIndex(block[len(header):]); end != nil {
		block = block[:len(header)+end[0]]
	}
	return block
}

// jsonWireKeys returns the sorted JSON object keys json.Marshal emits for v.
func jsonWireKeys(t *testing.T, v any) []string {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
