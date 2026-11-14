package userapi

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/db"
)

// The message list, search and GET /user/messages/{id} encode db.DBMessage, and the
// filter endpoints SieveScriptRequest and SieveScriptResponse. The spec described a
// different message (mailbox, to as a string, from and recipients as {name, email},
// headers, body_text, body_html, attachments) and a filter with content, size and
// created_at; a client sending content got 400 "Script content is required" (#459).
// These pin the schemas to the keys json.Marshal emits.

func TestOpenAPIMessageMatchesWireFormat(t *testing.T) {
	// recipients is declared but never set: setRecipients fills from, to, cc and bcc.
	assertSchemaMatchesWire(t, "Message", filledWireKeys[db.DBMessage](t), "recipients")
}

func TestOpenAPIFilterMatchesWireFormat(t *testing.T) {
	assertSchemaMatchesWire(t, "Filter", filledWireKeys[SieveScriptResponse](t))
}

func TestOpenAPIFilterRequestMatchesWireFormat(t *testing.T) {
	assertSchemaMatchesWire(t, "FilterRequest", filledWireKeys[SieveScriptRequest](t))
}

func assertSchemaMatchesWire(t *testing.T, schema string, wire []string, neverSent ...string) {
	t.Helper()
	wire = slices.DeleteFunc(wire, func(k string) bool { return slices.Contains(neverSent, k) })
	documented := openAPISchemaProperties(t, schema)
	if strings.Join(documented, ",") != strings.Join(wire, ",") {
		t.Fatalf("OpenAPI %s properties do not match the wire format\n  spec: %v\n  wire: %v", schema, documented, wire)
	}
}

// filledWireKeys returns the sorted JSON keys json.Marshal emits for a T whose every
// field holds a non-zero value, so omitempty fields are included.
func filledWireKeys[T any](t *testing.T) []string {
	t.Helper()
	var v T
	rv := reflect.ValueOf(&v).Elem()
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Field(i)
		switch f.Kind() {
		case reflect.String:
			f.SetString("x")
		case reflect.Int, reflect.Int64:
			f.SetInt(1)
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 1, 1))
		case reflect.Pointer:
			f.Set(reflect.New(f.Type().Elem()))
		case reflect.Struct: // time.Time: never omitted
		default:
			t.Fatalf("%s.%s: unhandled kind %s", rv.Type(), rv.Type().Field(i).Name, f.Kind())
		}
	}
	return jsonWireKeys(t, v)
}
