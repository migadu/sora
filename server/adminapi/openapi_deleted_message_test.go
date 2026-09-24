package adminapi

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/migadu/sora/db"
)

// The deleted-messages endpoints encode db.DeletedMessage directly, so the wire keys are
// the Go field names. The spec and docs said snake_case (mailbox_path, content_hash, ...)
// for as long as the endpoint existed; clients written against them read nothing. This
// pins the OpenAPI schema to what json.Marshal actually emits, so the two cannot drift.
func TestOpenAPIDeletedMessageMatchesWireFormat(t *testing.T) {
	spec, err := os.ReadFile("admin_api_openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}

	start := strings.Index(string(spec), "\n    DeletedMessage:\n")
	if start < 0 {
		t.Fatal("DeletedMessage schema not found in admin_api_openapi.yaml")
	}
	block := string(spec)[start+1:]
	if end := regexp.MustCompile(`\n    [A-Za-z]`).FindStringIndex(block[len("    DeletedMessage:"):]); end != nil {
		block = block[:len("    DeletedMessage:")+end[0]]
	}
	var documented []string
	for _, m := range regexp.MustCompile(`(?m)^        ([A-Za-z_]+):\s*$`).FindAllStringSubmatch(block, -1) {
		documented = append(documented, m[1])
	}

	encoded, err := json.Marshal(db.DeletedMessage{})
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
		t.Fatalf("OpenAPI DeletedMessage properties do not match the wire format\n  spec: %v\n  wire: %v", documented, wire)
	}
}
