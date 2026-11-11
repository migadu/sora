package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"github.com/migadu/sora/tlsmanager"
)

// globalTLSDeps is a node with the global [tls] manager enabled (file provider).
func globalTLSDeps(t *testing.T) *serverDependencies {
	t.Helper()
	manager, err := tlsmanager.New(config.TLSConfig{
		Enabled:  true,
		Provider: "file",
		CertFile: "../../testdata/sora.crt",
		KeyFile:  "../../testdata/sora.key",
	}, nil)
	if err != nil {
		t.Fatalf("tlsmanager.New: %v", err)
	}
	return &serverDependencies{
		storage:       &storage.S3Storage{},
		resilientDB:   &resilient.ResilientDatabase{},
		uploadWorker:  &uploader.UploadWorker{},
		cacheInstance: &cache.Cache{},
		tlsManager:    manager,
		hostname:      "localhost",
		config:        config.NewDefaultConfig(),
		serverManager: &serverManager{},
	}
}

// The example config's global-TLS backend: tls = true and no certificate files.
func globalTLSBackendConfig(t *testing.T, serverType string) config.ServerConfig {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return config.ServerConfig{Type: serverType, Name: serverType + "-global-tls", Addr: addr, TLS: true}
}

// expectTLSGreeting waits for the backend to listen and requires it to speak
// TLS with the given greeting; a startup error fails the test.
func expectTLSGreeting(t *testing.T, addr, greeting string, errChan chan error) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		select {
		case err := <-errChan:
			t.Fatalf("backend failed to start: %v", err)
		default:
		}
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("backend did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("backend with tls = true under global [tls] must listen with TLS, but the TLS handshake failed: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if line, err := bufio.NewReader(conn).ReadString('\n'); err != nil || !strings.HasPrefix(line, greeting) {
		t.Fatalf("greeting over TLS = %q, %v", line, err)
	}
}

// An imap backend with tls = true and no certificate files is served with the
// global [tls] manager's certificate, as config.toml.example documents (#224).
func TestDynamicIMAPServerUsesGlobalTLS(t *testing.T) {
	deps := globalTLSDeps(t)
	serverConfig := globalTLSBackendConfig(t, "imap")
	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		startDynamicIMAPServer(ctx, deps, serverConfig, errChan)
	}()
	t.Cleanup(func() { cancel(); <-done })

	expectTLSGreeting(t, serverConfig.Addr, "* OK", errChan)
}

// Likewise for a pop3 backend (#224).
func TestDynamicPOP3ServerUsesGlobalTLS(t *testing.T) {
	deps := globalTLSDeps(t)
	serverConfig := globalTLSBackendConfig(t, "pop3")
	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		startDynamicPOP3Server(ctx, deps, serverConfig, errChan)
	}()
	t.Cleanup(func() { cancel(); <-done })

	expectTLSGreeting(t, serverConfig.Addr, "+OK", errChan)
}
