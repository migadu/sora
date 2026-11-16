package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"
)

func TestMaskRawQueryAmbiguousComponents(t *testing.T) {
	m := SecretMask
	for _, tc := range []struct{ name, raw, want string }{
		{"more padding", "Zml4dHVyZQ===", m},
		{"padding alone", "===", m},
		{"encoded bare padding", "Zml4dHVyZQ%3D%3D", m},
		{"encoded name and value", "sig%5Fid=fixture%3D%3D", "sig%5Fid=" + m},
		{"multiple separators in value", "sig=fixture=more==", "sig=" + m},
		{"empty components", "&debug=&&Zml4dHVyZQ==&", "&" + m + "&&" + m + "&"},
		{"semicolon within named value", "sig=fixture;other=fixture", "sig=" + m},
		{"literal templates", "email=$email&ip=$ip&debug=", "email=$email&ip=$ip&" + m},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := "https://example.invalid/review?" + tc.raw + "#fragment"
			want := "https://example.invalid/review?" + tc.want + "#fragment"
			if MaskEndpointURL(endpoint) != want {
				t.Fatal("dummy endpoint masking mismatch")
			}
			cfg := Config{Relay: RelayConfig{HTTPURL: endpoint}}
			MaskSecrets(&cfg)
			if cfg.Relay.HTTPURL != want {
				t.Fatal("dummy config masking mismatch")
			}
			masked := MaskURLError(fmt.Errorf("dummy wrapper: %w", &url.Error{
				Op: "Post", URL: endpoint, Err: context.DeadlineExceeded,
			}))
			var shown *url.Error
			var timeout net.Error
			if !errors.As(masked, &shown) || shown.URL != want ||
				!errors.Is(masked, context.DeadlineExceeded) || !errors.As(masked, &timeout) || !timeout.Timeout() {
				t.Fatal("dummy error masking lost URL or timeout classification")
			}
		})
	}
}
