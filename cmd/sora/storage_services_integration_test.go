//go:build integration

package main

import (
	"context"
	"os"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/errors"
)

// A node that runs the User API without imap, lmtp or pop3 still serves message bodies
// (GET /user/messages/{id}/body and /raw) from S3, so it needs the [s3] connection; the
// cache, uploader and cleanup machinery of the mail services stays off. Without [s3] it
// still starts, serving everything but bodies.
func TestInitializeServices_UserAPIOnlyNode(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}
	userAPINode := func() config.Config {
		cfg := config.NewDefaultConfig()
		cfg.Database = config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
			Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: dbName,
		}}
		cfg.DynamicServers = []config.ServerConfig{{
			Type: "http_user_api", Name: "user-api", Addr: "127.0.0.1:0",
			JWTSecret: "test-secret-key-at-least-32-bytes!!",
		}}
		return cfg
	}
	initialize := func(t *testing.T, cfg config.Config) *serverDependencies {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		deps, err := initializeServices(ctx, cfg, errors.NewErrorHandler())
		if err != nil {
			t.Fatalf("initializeServices: %v", err)
		}
		t.Cleanup(func() {
			if deps.resilientDB != nil {
				deps.resilientDB.Close()
			}
		})
		return deps
	}

	t.Run("with [s3]", func(t *testing.T) {
		cfg := userAPINode()
		cfg.S3 = config.S3Config{Endpoint: "127.0.0.1:9", DisableTLS: true, AccessKey: "test", SecretKey: "test", Bucket: "test"}
		deps := initialize(t, cfg)
		if deps.storage == nil {
			t.Error("no S3 storage on a User API node with [s3] configured: /body and /raw would answer 503 forever")
		}
		if deps.uploadWorker != nil || deps.cleanupWorker != nil || deps.cacheInstance != nil {
			t.Error("mail-service cache/uploader/cleaner started on a node without imap, lmtp or pop3")
		}
	})

	t.Run("without [s3]", func(t *testing.T) {
		deps := initialize(t, userAPINode())
		if deps.storage != nil {
			t.Error("S3 storage created without an [s3] section")
		}
	})
}
