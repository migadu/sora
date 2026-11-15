package config

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// Route-only proxies expire cached routes by positive_ttl; neither performs
// password-aware revalidation. Only an explicit setting needs this warning.
func TestRouteOnlyProxyRevalidationWarning(t *testing.T) {
	for _, typ := range []string{"lmtp_proxy", "user_api_proxy"} {
		for _, explicit := range []bool{false, true} {
			var s ServerConfig
			input := "type = \"" + typ + "\"\n[lookup_cache]\nenabled = true\n"
			if explicit {
				input += "positive_revalidation_window = \"30s\"\n"
			}
			if _, err := toml.Decode(input, &s); err != nil {
				t.Fatal(err)
			}
			var count int
			for _, warning := range warningsFor(s) {
				if strings.Contains(warning, "'lookup_cache.positive_revalidation_window'") {
					count++
				}
			}
			want := 0
			if explicit {
				want = 1
			}
			if count != want {
				t.Errorf("%s explicit=%v: got %d revalidation warnings, want %d", typ, explicit, count, want)
			}
		}
	}
}
