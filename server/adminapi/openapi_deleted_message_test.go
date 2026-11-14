package adminapi

import (
	"strings"
	"testing"

	"github.com/migadu/sora/db"
)

// The deleted-messages endpoints encode db.DeletedMessage directly, so the wire keys are
// the Go field names. The spec and docs said snake_case (mailbox_path, content_hash, ...)
// for as long as the endpoint existed; clients written against them read nothing. This
// pins the OpenAPI schema to what json.Marshal actually emits, so the two cannot drift.
func TestOpenAPIDeletedMessageMatchesWireFormat(t *testing.T) {
	documented := schemaProperties(t, "DeletedMessage")
	wire := wireKeys(t, db.DeletedMessage{})
	if strings.Join(documented, ",") != strings.Join(wire, ",") {
		t.Fatalf("OpenAPI DeletedMessage properties do not match the wire format\n  spec: %v\n  wire: %v", documented, wire)
	}
}
