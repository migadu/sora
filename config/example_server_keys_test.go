package config

import (
	"bufio"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// tomlFields maps the toml keys a struct decodes to their field types.
func tomlFields(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
		if name == "" || name == "-" {
			continue
		}
		fields[name] = f.Type
	}
	return fields
}

// structOf strips pointers and slices down to the struct a table decodes into.
func structOf(t reflect.Type) (reflect.Type, bool) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	return t, t.Kind() == reflect.Struct
}

// Every key config.toml.example writes in a [[server]] block, commented out or not,
// is one the loader reads into ServerConfig (#542). A documented key the struct
// lacks is reported as unknown at startup and silently ignored.
func TestConfigExampleServerKeysExist(t *testing.T) {
	f, err := os.Open("../config.toml.example")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	header := regexp.MustCompile(`^\s*(#?)\s*\[\[?([a-z_.]+)\]\]?\s*(#.*)?$`)
	// A key line: "key = value" or "# key = value", where value starts like a TOML
	// value (prose such as "#   context_timeout = (dial_timeout + ...)" does not).
	keyLine := regexp.MustCompile(`^\s*(#?)\s*([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*)\s*=\s*(["'\[{0-9+-]|true|false)`)

	// section is the ServerConfig (sub)table the next key belongs to, nil outside
	// one. A commented-out header scopes only the commented-out lines after it: a
	// live key line after "# [[server.client_filters]]" is still in the live table.
	var section, live reflect.Type
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if m := header.FindStringSubmatch(line); m != nil {
			section = nil
			if m[1] == "" {
				live = nil
			}
			path := strings.Split(m[2], ".")
			if path[0] != "server" {
				continue
			}
			typ := reflect.TypeOf(ServerConfig{})
			for _, part := range path[1:] {
				ft, ok := tomlFields(typ)[part]
				if !ok {
					t.Errorf("config.toml.example:%d: table [%s] is not a ServerConfig table", n, m[2])
					typ = nil
					break
				}
				if typ, ok = structOf(ft); !ok {
					typ = nil
					break
				}
			}
			section = typ
			if m[1] == "" {
				live = typ
			}
			continue
		}
		m := keyLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if m[1] == "" {
			section = live
		}
		if section == nil {
			continue
		}
		typ := section
		parts := strings.Split(m[2], ".")
		for i, part := range parts {
			ft, ok := tomlFields(typ)[part]
			if !ok {
				t.Errorf("config.toml.example:%d: %q is not a key the config reads", n, m[2])
				break
			}
			if i < len(parts)-1 {
				if typ, ok = structOf(ft); !ok {
					t.Errorf("config.toml.example:%d: %q is not a table", n, strings.Join(parts[:i+1], "."))
					break
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}
