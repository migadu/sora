package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestMaskURLErrorKeepsClassification(t *testing.T) {
	for _, endpoint := range []string{
		"https://fixture-user:fixture-password@host.invalid/%zz?token=fixture-token",
		"https://fixture-user:fixture-password@bad host.invalid/send",
	} {
		_, original := url.Parse(endpoint)
		if original == nil {
			t.Fatal("fixture URL unexpectedly parsed")
		}
		cause := original.(*url.Error).Err
		masked := MaskURLError(original)
		if !errors.Is(masked, cause) {
			t.Errorf("masking lost the original parse cause %T", cause)
		}
		var escape url.EscapeError
		var host url.InvalidHostError
		if _, ok := cause.(url.EscapeError); ok && !errors.As(masked, &escape) {
			t.Error("masking lost url.EscapeError classification")
		}
		if _, ok := cause.(url.InvalidHostError); ok && !errors.As(masked, &host) {
			t.Error("masking lost url.InvalidHostError classification")
		}
		if strings.Contains(masked.Error(), "fixture") {
			t.Errorf("parse error leaked credentials: %v", masked)
		}
	}

	const endpoint = "https://fixture-user:fixture-password@host.invalid/send?token=fixture-token"
	original := &url.Error{Op: "Get", URL: endpoint, Err: context.DeadlineExceeded}
	wrapped := fmt.Errorf("lookup failed: %w", original)
	masked := MaskURLError(wrapped)
	if strings.Contains(masked.Error(), "fixture") {
		t.Errorf("preformatted wrapper leaked credentials: %v", masked)
	}
	var network net.Error
	if !errors.Is(masked, context.DeadlineExceeded) || !errors.As(masked, &network) || !network.Timeout() {
		t.Errorf("masking lost cancellation or network timeout classification: %v", masked)
	}

	// A source error can quote another URL and still provide net.Error methods.
	source := endpointTimeoutError{endpoint: endpoint}
	masked = MaskURLError(&url.Error{Op: "Get", URL: "https://host.invalid", Err: source})
	if !errors.Is(masked, source) || !errors.As(masked, &network) || !network.Timeout() || !network.Temporary() {
		t.Errorf("masking lost source-error classification: %v", masked)
	}
	if strings.Contains(masked.Error(), "fixture") {
		t.Errorf("source error leaked credentials: %v", masked)
	}
}

type endpointTimeoutError struct{ endpoint string }

func (e endpointTimeoutError) Error() string { return fmt.Sprintf("timeout reaching %q", e.endpoint) }
func (endpointTimeoutError) Timeout() bool   { return true }
func (endpointTimeoutError) Temporary() bool { return true }

func TestMaskURLErrorHidesMalformedRedirect(t *testing.T) {
	for _, location := range []string{
		"https://fixture-user:fixture/password@host.invalid/send?token=fixture-token",
		"//fixture-user:fixture/password@host.invalid/send?token=fixture-token",
		"/%zz?token=fixture-token",
	} {
		t.Run(location, func(t *testing.T) {
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", location)
				w.WriteHeader(http.StatusMovedPermanently)
			}))
			defer endpoint.Close()
			client := endpoint.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			_, err := client.Get(endpoint.URL)
			if err == nil {
				t.Fatal("malformed redirect was unexpectedly accepted")
			}
			masked := MaskURLError(err)
			if strings.Contains(masked.Error(), "fixture") {
				t.Errorf("malformed redirect leaked credentials: %v", masked)
			}
			if !strings.Contains(masked.Error(), "failed to parse Location header") ||
				(!strings.Contains(masked.Error(), "invalid port") && !strings.Contains(masked.Error(), "invalid URL escape")) {
				t.Errorf("masking lost useful error categories: %v", masked)
			}
		})
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
