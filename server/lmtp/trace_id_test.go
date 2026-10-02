package lmtp

import (
	"reflect"
	"strings"
	"testing"
)

func TestTraceIDFromHeader(t *testing.T) {
	cases := []struct{ in, want string }{
		{"9f86d081884c7d65", "9f86d081884c7d65"},
		{"  9f86d081884c7d65 ", "9f86d081884c7d65"},
		{"abc-DEF_1.2", "abc-DEF_1.2"},
		{"", ""},
		{"has space", ""},
		{"inject\nlevel=ERROR", ""},
		{`quote"d`, ""},
		{"a=b", ""},
		{strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{strings.Repeat("a", 65), ""},
	}
	for _, c := range cases {
		if got := traceIDFromHeader(c.in); got != c.want {
			t.Errorf("traceIDFromHeader(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestWithTrace(t *testing.T) {
	s := &LMTPSession{}
	kv := []any{"mailbox", "INBOX"}

	if got := s.withTrace(kv); !reflect.DeepEqual(got, kv) {
		t.Errorf("without trace id: got %v, want %v", got, kv)
	}

	s.traceID = "9f86d081884c7d65"
	got := s.withTrace(kv)
	want := []any{"mailbox", "INBOX", "trace_id", "9f86d081884c7d65"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("with trace id: got %v, want %v", got, want)
	}
	// The caller's slice must not be modified.
	if len(kv) != 2 {
		t.Errorf("caller's slice changed: %v", kv)
	}
}
