package main

import (
	"testing"

	"github.com/migadu/sora/config"
)

// TestBuildAdminAPIServerOptions_ThreadsSieveExtensions covers the one line that connects
// [sieve] enabled_extensions to the Admin API delivery path. The Admin API compiles a
// user's Sieve script with whatever set it is handed, and a compile failure there is
// swallowed into a plain INBOX keep - so if this hop is dropped, an opted-in extension
// (say editheader) silently stops working over /admin/mail/deliver while it keeps working
// over LMTP, with nothing failing loudly.
//
// The other end of the same option is covered end-to-end by
// integration_tests/adminapi.TestAdminAPI_DeliverMail_HonoursConfiguredSieveExtensions.
func TestBuildAdminAPIServerOptions_ThreadsSieveExtensions(t *testing.T) {
	configured := []string{"fileinto", "vacation", "editheader"}
	deps := &serverDependencies{
		config: config.Config{
			Sieve: config.SieveConfig{EnabledExtensions: configured},
		},
	}

	options := buildAdminAPIServerOptions(deps, config.ServerConfig{Name: "admin-api", Addr: ":8080"})

	if len(options.SieveExtensions) != len(configured) {
		t.Fatalf("[sieve] enabled_extensions did not reach the Admin API options: got %v, want %v",
			options.SieveExtensions, configured)
	}
	for i, ext := range configured {
		if options.SieveExtensions[i] != ext {
			t.Fatalf("[sieve] enabled_extensions altered on the way to the Admin API options: got %v, want %v",
				options.SieveExtensions, configured)
		}
	}
}
