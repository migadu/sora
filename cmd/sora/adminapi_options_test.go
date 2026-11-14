package main

import (
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server/relayqueue"
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

// TestBuildAdminAPIServerOptions_ThreadsRelayWorker covers the line that lets
// /admin/mail/deliver wake the relay worker (#327). If it is dropped, a redirect or
// vacation reply the Admin API queues waits for the worker's next pass, and nothing
// fails. A node without [relay] has no worker, and the option must then be a nil
// interface: one holding a nil *relayqueue.Worker would be called and dereference it.
func TestBuildAdminAPIServerOptions_ThreadsRelayWorker(t *testing.T) {
	serverConfig := config.ServerConfig{Name: "admin-api", Addr: ":8080"}

	t.Run("relay worker", func(t *testing.T) {
		worker := relayqueue.NewWorker(nil, nil, time.Minute, 0, 0, 0, 0, nil)
		options := buildAdminAPIServerOptions(&serverDependencies{relayWorker: worker}, serverConfig)
		if options.RelayWorker != worker {
			t.Fatalf("the relay worker did not reach the Admin API options: got %#v", options.RelayWorker)
		}
	})

	t.Run("no relay", func(t *testing.T) {
		options := buildAdminAPIServerOptions(&serverDependencies{}, serverConfig)
		if options.RelayWorker != nil {
			t.Fatalf("a node without a relay worker must leave the option nil, got %#v", options.RelayWorker)
		}
	})
}
