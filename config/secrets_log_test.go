package config

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Endpoint URLs reach the log as the config dump shows them (#806).
func TestMaskEndpointURL(t *testing.T) {
	const m = SecretMask
	for _, tc := range []struct{ in, want string }{
		{"https://relay.example.invalid/send", "https://relay.example.invalid/send"},
		{"https://lookup.example.invalid/users/fixture@example.com", "https://lookup.example.invalid/users/fixture@example.com"},
		{"https://fixture-user:fixture-password@relay.example.invalid/send?api_key=fixture-query-secret",
			"https://%2A%2A%2AMASKED%2A%2A%2A:%2A%2A%2AMASKED%2A%2A%2A@relay.example.invalid/send?api_key=" + m},
		{"https://fixture-user:fixture/password@relay.example.invalid/send", m},
		// Without a scheme the masker cannot find the userinfo or the query.
		{"fixture-user:fixture-password@relay.example.invalid/send", m},
		{"relay.example.invalid/send?api_key=fixture-query-secret", m},
		{"relay.example.invalid:25", "relay.example.invalid:25"},
	} {
		if got := MaskEndpointURL(tc.in); got != tc.want {
			t.Errorf("MaskEndpointURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// net/http quotes the request URL in its errors with the user name and the query
// (it replaces only the password), and url.Parse quotes the whole URL it refuses,
// its reason a piece of it (#806).
func TestMaskURLError(t *testing.T) {
	if MaskURLError(nil) != nil {
		t.Error("MaskURLError(nil) != nil")
	}
	plain := errors.New("fixture-free")
	if MaskURLError(plain) != plain {
		t.Error("an error without a *url.Error was changed")
	}

	_, parseErr := http.NewRequest("POST", "https://fixture-user:fixture/password@relay.example.invalid/send", nil)
	// As http.Client.Do returns it.
	clientErr := error(&url.Error{
		Op:  "Post",
		URL: "https://fixture-user:***@relay.example.invalid/send?api_key=fixture-query-secret",
		Err: context.DeadlineExceeded,
	})
	_, noCredentialsErr := http.NewRequest("POST", "https://relay.example.invalid:80a/send", nil)
	for _, tc := range []struct {
		name string
		err  error
		want []string // substrings the masked error keeps
	}{
		{"parse", parseErr, []string{`parse "` + SecretMask + `"`, "invalid port"}},
		{"client", clientErr, []string{"relay.example.invalid/send?api_key=" + SecretMask, "deadline exceeded"}},
		{"no credentials", noCredentialsErr, []string{`"https://relay.example.invalid:80a/send"`, `invalid port ":80a" after host`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := MaskURLError(tc.err)
			if got != tc.err {
				t.Errorf("MaskURLError returned another error: %v", got)
			}
			if strings.Contains(got.Error(), "fixture") {
				t.Errorf("masked error still quotes a credential: %v", got)
			}
			for _, want := range tc.want {
				if !strings.Contains(got.Error(), want) {
					t.Errorf("masked error %q does not contain %q", got, want)
				}
			}
		})
	}
	if !errors.Is(clientErr, context.DeadlineExceeded) {
		t.Error("masking broke the error chain")
	}
}
