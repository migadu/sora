package userapi

import (
	"encoding/json"
	"math"
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
// These pin the schemas to the keys json.Marshal emits and to the JSON type of each.

func TestOpenAPIMessageMatchesWireFormat(t *testing.T) {
	// recipients is declared but never set: setRecipients fills from, to, cc and bcc.
	assertSchemaMatchesWire(t, "Message", filledWireShapes[db.DBMessage](t), "recipients")
}

func TestOpenAPIFilterMatchesWireFormat(t *testing.T) {
	assertSchemaMatchesWire(t, "Filter", filledWireShapes[SieveScriptResponse](t))
}

func TestOpenAPIFilterRequestMatchesWireFormat(t *testing.T) {
	assertSchemaMatchesWire(t, "FilterRequest", filledWireShapes[SieveScriptRequest](t))
}

// assertSchemaMatchesWire compares the schema's "name: type" list with the wire's,
// leaving out the keys in neverSent.
func assertSchemaMatchesWire(t *testing.T, schema string, wire []string, neverSent ...string) {
	t.Helper()
	wire = slices.DeleteFunc(wire, func(s string) bool {
		key, _, _ := strings.Cut(s, ": ")
		return slices.Contains(neverSent, key)
	})
	documented := strings.Join(openAPIPropertyShapes(t, schema), ", ")
	if got := strings.Join(wire, ", "); documented != got {
		t.Fatalf("OpenAPI %s properties do not match the wire format\n  spec: %s\n  wire: %s", schema, documented, got)
	}
}

// filledWireShapes returns "key: type" for each JSON key json.Marshal emits for a T
// whose every field holds a non-zero value, so omitempty fields are included, sorted.
func filledWireShapes[T any](t *testing.T) []string {
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
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	shapes := make([]string, 0, len(fields))
	for k, value := range fields {
		shapes = append(shapes, k+": "+jsonShape(value))
	}
	slices.Sort(shapes)
	return shapes
}

// jsonShape names a decoded JSON value's type as OpenAPI does; an array is named with
// its first element's type.
func jsonShape(v any) string {
	switch v := v.(type) {
	case string:
		return "string"
	case bool:
		return "boolean"
	case float64:
		if v == math.Trunc(v) {
			return "integer"
		}
		return "number"
	case []any:
		if len(v) == 0 {
			return "array"
		}
		return "array of " + jsonShape(v[0])
	case map[string]any:
		return "object"
	}
	return "null"
}

// openAPIPropertyShapes returns "name: type" for each property of the named schema,
// sorted. An array's type names its items' type, and a $ref is followed.
func openAPIPropertyShapes(t *testing.T, schema string) []string {
	t.Helper()
	type property struct {
		name string
		body []string
	}
	var props []*property
	var cur *property
	for _, line := range strings.Split(openAPISchemaBlock(t, schema), "\n") {
		if m := openAPIPropertyName.FindStringSubmatch(line); m != nil {
			cur = &property{name: m[1]}
			props = append(props, cur)
		} else if cur != nil && strings.HasPrefix(line, strings.Repeat(" ", 10)) {
			cur.body = append(cur.body, line)
		} else if line != "" {
			cur = nil
		}
	}
	shapes := make([]string, 0, len(props))
	for _, p := range props {
		shapes = append(shapes, p.name+": "+openAPIShape(t, p.name, p.body, 10))
	}
	slices.Sort(shapes)
	return shapes
}

// openAPIShape returns the type that body, a schema's lines with its keys indented by
// indent spaces, declares.
func openAPIShape(t *testing.T, what string, body []string, indent int) string {
	t.Helper()
	pad := strings.Repeat(" ", indent)
	for _, line := range body {
		if ref, ok := strings.CutPrefix(line, pad+"$ref: '#/components/schemas/"); ok {
			ref = strings.TrimSuffix(ref, "'")
			return openAPIShape(t, ref, strings.Split(openAPISchemaBlock(t, ref), "\n")[1:], 6)
		}
	}
	for _, line := range body {
		typ, ok := strings.CutPrefix(line, pad+"type: ")
		if !ok {
			continue
		}
		if typ != "array" {
			return typ
		}
		for i, items := range body {
			if items != pad+"items:" {
				continue
			}
			var itemBody []string
			for _, l := range body[i+1:] {
				if !strings.HasPrefix(l, pad+"  ") {
					break
				}
				itemBody = append(itemBody, l)
			}
			return "array of " + openAPIShape(t, what+" items", itemBody, indent+2)
		}
		t.Fatalf("%s: array without items", what)
	}
	t.Fatalf("%s: no type or $ref", what)
	return ""
}
