package proxy

import "testing"

// TestValidateRemoteLookupURL verifies that a plaintext remote-lookup endpoint is
// rejected for non-loopback hosts (audit M3), while https and loopback http are allowed.
func TestValidateRemoteLookupURL(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"https://lookup.example.com/auth", false},
		{"https://example.com", false},
		{"http://localhost:8080/lookup", false},
		{"http://127.0.0.1/lookup", false},
		{"http://[::1]:9000/lookup", false},
		{"http://127.0.0.5/lookup", false}, // 127.0.0.0/8 is loopback
		{"http://example.com/lookup", true},
		{"http://10.0.0.5:8080/lookup", true},
		{"http://lookup.internal/auth", true},
		{"ftp://example.com", true},
	}
	for _, c := range cases {
		err := validateRemoteLookupURL(c.url)
		if (err != nil) != c.wantErr {
			t.Errorf("validateRemoteLookupURL(%q) err=%v, wantErr=%v", c.url, err, c.wantErr)
		}
	}
}
