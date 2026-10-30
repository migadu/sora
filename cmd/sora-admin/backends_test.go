package main

import "testing"

func TestNormalizeBackendHost(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"storage2.example.com", "storage2.example.com", false},
		{" Storage2.Example.COM. ", "storage2.example.com", false},
		{"10.0.0.5", "10.0.0.5", false},
		{"2001:db8:0::1", "2001:db8::1", false}, // bare IPv6, canonicalized
		{"[2001:db8::1]", "2001:db8::1", false},
		{"storage2.example.com:143", "", true}, // a port would cover one protocol only
		{"10.0.0.5:24", "", true},
		{"[2001:db8::1]:143", "", true},
		{"", "", true},
		{"a b", "", true},
	}
	for _, c := range cases {
		got, err := normalizeBackendHost(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("normalizeBackendHost(%q) error = %v, wantErr %v", c.in, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("normalizeBackendHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
