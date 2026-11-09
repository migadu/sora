package config

import (
	"reflect"
	"strings"
)

// RestartRequiredChanges names the settings that differ between s, the config a server
// started with, and next, the one a reload read for it, less reloadable, the settings
// the server's ReloadConfig applies. A name is the TOML key, dotted inside a table
// ("timeouts.command_timeout"); names come in declaration order. A table absent on one
// side counts as present with every value zero, so adding [server.timeouts] with only
// command_timeout set changes timeouts.command_timeout and nothing else. A list, or an
// array of tables such as client_filters, is one setting.
func (s *ServerConfig) RestartRequiredChanges(next ServerConfig, reloadable []string) []string {
	applied := make(map[string]bool, len(reloadable))
	for _, key := range reloadable {
		applied[key] = true
	}
	var changed []string
	walkTOMLKeys("", reflect.ValueOf(*s), reflect.ValueOf(next), func(key string, was, now reflect.Value) {
		if !applied[key] && !reflect.DeepEqual(was.Interface(), now.Interface()) {
			changed = append(changed, key)
		}
	})
	return changed
}

// ServerConfigKeys lists every setting RestartRequiredChanges can name, in the order
// it names them.
func ServerConfigKeys() []string {
	var keys []string
	zero := reflect.ValueOf(ServerConfig{})
	walkTOMLKeys("", zero, zero, func(key string, _, _ reflect.Value) {
		keys = append(keys, key)
	})
	return keys
}

// walkTOMLKeys calls visit with the TOML key and both values of every exported leaf
// field of a and b, two values of one struct type. A struct, or a pointer to one, is a
// TOML table and is walked, a nil pointer as the zero struct. Anything else is a leaf.
func walkTOMLKeys(prefix string, a, b reflect.Value, visit func(key string, a, b reflect.Value)) {
	t := a.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		key := tomlKey(field)
		if key == "-" {
			continue
		}
		if prefix != "" {
			key = prefix + "." + key
		}
		if table, ok := tomlTable(field.Type); ok {
			walkTOMLKeys(key, tableValue(a.Field(i), table), tableValue(b.Field(i), table), visit)
			continue
		}
		visit(key, a.Field(i), b.Field(i))
	}
}

// tomlKey is the key the decoder reads a field from: the name in its toml tag, or the
// field's own name when the tag has none.
func tomlKey(field reflect.StructField) string {
	if name, _, _ := strings.Cut(field.Tag.Get("toml"), ","); name != "" {
		return name
	}
	return field.Name
}

// tomlTable returns the struct a field of type t decodes a TOML table into, if it is one.
func tomlTable(t reflect.Type) (reflect.Type, bool) {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() == reflect.Struct {
		return t, true
	}
	return nil, false
}

// tableValue is the struct behind v: itself, what it points to, or the zero table for
// a nil pointer.
func tableValue(v reflect.Value, table reflect.Type) reflect.Value {
	if v.Kind() != reflect.Pointer {
		return v
	}
	if v.IsNil() {
		return reflect.Zero(table)
	}
	return v.Elem()
}
