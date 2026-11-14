package adminapi

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// GET /admin/connections lists ConnectionInfo entries and GET /admin/connections/user/{email}
// UserConnectionInfo entries: one per account and connection tracker, with snake_case keys.
// The spec described a per-session record with Go field names (ID, ClientAddr,
// ConnectedAt, ...) that no handler ever sent, so a client generated from it read nothing.
// This pins both schemas to what json.Marshal emits for the entry types.
func TestOpenAPIConnectionEntriesMatchWireFormat(t *testing.T) {
	spec, err := os.ReadFile("admin_api_openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	nextSchema := regexp.MustCompile(`\n    [A-Za-z]`)
	property := regexp.MustCompile(`(?m)^        ([A-Za-z_]+):\s*$`)

	for _, tc := range []struct {
		schema string
		entry  any
	}{
		{"ConnectionInfo", ConnectionInfo{}},
		{"UserConnectionInfo", UserConnectionInfo{}},
	} {
		t.Run(tc.schema, func(t *testing.T) {
			header := "    " + tc.schema + ":"
			start := strings.Index(string(spec), "\n"+header+"\n")
			if start < 0 {
				t.Fatalf("%s schema not found in admin_api_openapi.yaml", tc.schema)
			}
			block := string(spec)[start+1:]
			if end := nextSchema.FindStringIndex(block[len(header):]); end != nil {
				block = block[:len(header)+end[0]]
			}
			var documented []string
			for _, m := range property.FindAllStringSubmatch(block, -1) {
				documented = append(documented, m[1])
			}

			encoded, err := json.Marshal(tc.entry)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			var wire []string
			for k := range fields {
				wire = append(wire, k)
			}

			sort.Strings(documented)
			sort.Strings(wire)
			if strings.Join(documented, ",") != strings.Join(wire, ",") {
				t.Fatalf("OpenAPI %s properties do not match the wire format\n  spec: %v\n  wire: %v", tc.schema, documented, wire)
			}
		})
	}
}
