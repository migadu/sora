package managesieve

import "testing"

// TestQuoteSieveString verifies RFC 5804 quoted-string escaping so an embedded
// double-quote or backslash in a script name / tag cannot break response framing.
func TestQuoteSieveString(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{``, `""`},
		{`inbox`, `"inbox"`},
		{`my"script`, `"my\"script"`},
		{`back\slash`, `"back\\slash"`},
		{`a"b\c`, `"a\"b\\c"`},
		{`\"`, `"\\\""`},
	}
	for _, c := range cases {
		if got := quoteSieveString(c.in); got != c.want {
			t.Errorf("quoteSieveString(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
