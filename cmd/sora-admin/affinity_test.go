package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/affinitycache"
	"github.com/migadu/sora/server/adminapi"
)

const (
	affinityHelperEnv = "SORA_ADMIN_AFFINITY_HELPER_ARGS"
	affinityAPIKey    = "test-admin-api-key-0123456789"
)

// TestAffinityCommandHelper is not a test: it is `sora-admin <args>`, run by the affinity
// command tests in a process of their own because the commands exit on failure.
func TestAffinityCommandHelper(t *testing.T) {
	args := os.Getenv(affinityHelperEnv)
	if args == "" {
		t.Skip("helper process for the affinity command tests")
	}
	os.Args = append([]string{"sora-admin"}, strings.Split(args, "\n")...)
	main()
}

// runAffinityCommand runs `sora-admin --config <configPath> affinity <args>` and returns
// its output and whether it exited 0.
func runAffinityCommand(t *testing.T, configPath string, args ...string) (string, bool) {
	t.Helper()
	full := append([]string{"--config", configPath, "affinity"}, args...)
	cmd := exec.Command(os.Args[0], "-test.run=^TestAffinityCommandHelper$")
	cmd.Env = append(os.Environ(), affinityHelperEnv+"="+strings.Join(full, "\n"))
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("running sora-admin affinity %v: %v", args, err)
	}
	return string(out), err == nil
}

// affinityTestManager holds affinities in a map, as the gossip affinity manager does.
type affinityTestManager struct {
	mu      sync.Mutex
	entries map[[2]string]string // {user, protocol} -> backend
}

func (m *affinityTestManager) SetBackend(username, backend, protocol string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[[2]string{username, protocol}] = backend
}

func (m *affinityTestManager) GetBackend(username, protocol string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	backend, ok := m.entries[[2]string{username, protocol}]
	return backend, ok
}

func (m *affinityTestManager) DeleteBackend(username, protocol string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, [2]string{username, protocol})
}

func (m *affinityTestManager) GetStats(ctx context.Context) map[string]any {
	return map[string]any{"enabled": true}
}

func (m *affinityTestManager) List() []affinitycache.AffinityEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var list []affinitycache.AffinityEntry
	for k, backend := range m.entries {
		list = append(list, affinitycache.AffinityEntry{
			Username: k[0], Protocol: k[1], Backend: backend,
			AssignedAt: now, ExpiresAt: now.Add(24 * time.Hour), NodeID: "node-1",
		})
	}
	return list
}

// startAffinityAdminAPI serves the Admin API with am on a free loopback port, over TLS
// with a self-signed certificate when withTLS is set, and returns its host:port.
func startAffinityAdminAPI(t *testing.T, am *affinityTestManager, withTLS bool) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	options := adminapi.ServerOptions{
		Name:            "admin-api",
		Addr:            addr,
		APIKey:          affinityAPIKey,
		AffinityManager: am,
		ValidBackends:   map[string][]string{"imap": {"192.0.2.21:143", "192.0.2.22:143"}, "pop3": {"192.0.2.21:110"}},
	}
	if withTLS {
		options.TLS = true
		options.TLSConfig = &tls.Config{Certificates: []tls.Certificate{affinityTestCert(t)}}
	}
	srv, err := adminapi.New(nil, options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv.Serve(ctx, make(chan error, 1))

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return addr
		}
		if time.Now().After(deadline) {
			t.Fatalf("Admin API did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func affinityTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writeAffinityConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// bothSectionsConfig names the Admin API at addr in [admin_cli] and in an
// http_admin_api [[server]] block, so the commands reach it whichever they read.
func bothSectionsConfig(t *testing.T, addr string) string {
	return writeAffinityConfig(t, fmt.Sprintf(`[admin_cli]
addr = "http://%[1]s"
api_key = %[2]q

[[server]]
type = "http_admin_api"
name = "admin-api"
addr = %[1]q
api_key = %[2]q
`, addr, affinityAPIKey))
}

// The affinity commands reach the Admin API named by [admin_cli], with its TLS
// settings, like every other HTTP command: on an admin host that has only [admin_cli]
// and an Admin API with tls = true.
func TestAffinityCommandsUseAdminCLI(t *testing.T) {
	am := &affinityTestManager{entries: map[[2]string]string{}}
	addr := startAffinityAdminAPI(t, am, true)
	configPath := writeAffinityConfig(t, fmt.Sprintf(`[admin_cli]
addr = "https://%s"
api_key = %q
insecure_skip_verify = true
`, addr, affinityAPIKey))

	out, ok := runAffinityCommand(t, configPath, "set", "--user", "anna@example.com", "--protocol", "imap", "--backend", "192.0.2.21:143")
	if !ok {
		t.Fatalf("affinity set failed:\n%s", out)
	}
	if backend, _ := am.GetBackend("anna@example.com", "imap"); backend != "192.0.2.21:143" {
		t.Fatalf("affinity set reported success, but the server holds %q:\n%s", backend, out)
	}

	out, ok = runAffinityCommand(t, configPath, "get", "--user", "anna@example.com", "--protocol", "imap")
	if !ok || !strings.Contains(out, "Backend: 192.0.2.21:143") {
		t.Errorf("affinity get (exit 0: %v) does not show the backend:\n%s", ok, out)
	}

	out, ok = runAffinityCommand(t, configPath, "delete", "--user", "anna@example.com", "--protocol", "imap")
	if !ok {
		t.Fatalf("affinity delete failed:\n%s", out)
	}
	if _, found := am.GetBackend("anna@example.com", "imap"); found {
		t.Errorf("affinity delete reported success, but the server still holds the affinity:\n%s", out)
	}
}

// `affinity get` shows an existing affinity, and reports a missing one without failing.
func TestAffinityGetReportsTheAffinity(t *testing.T) {
	am := &affinityTestManager{entries: map[[2]string]string{{"anna@example.com", "imap"}: "192.0.2.21:143"}}
	configPath := bothSectionsConfig(t, startAffinityAdminAPI(t, am, false))

	out, ok := runAffinityCommand(t, configPath, "get", "--user", "anna@example.com", "--protocol", "imap")
	if !ok || !strings.Contains(out, "Backend: 192.0.2.21:143") {
		t.Errorf("affinity get of an existing affinity (exit 0: %v) does not show its backend:\n%s", ok, out)
	}

	out, ok = runAffinityCommand(t, configPath, "get", "--user", "nobody@example.com", "--protocol", "imap")
	if !ok || !strings.Contains(out, "No affinity found for user nobody@example.com and protocol imap") {
		t.Errorf("affinity get of a missing affinity (exit 0: %v) does not report it as missing:\n%s", ok, out)
	}
}

// The address goes in the query string escaped: "+" is not a space, and "&" does not end
// the parameter (both are atext, RFC 5322 §3.2.3).
func TestAffinityCommandsEscapeTheAddress(t *testing.T) {
	for _, tc := range []struct {
		user    string
		misread string // the user an unescaped query names instead
	}{
		{"anna+tag@example.com", "anna tag@example.com"},
		{"a&b@example.com", "a"},
	} {
		t.Run(tc.user, func(t *testing.T) {
			am := &affinityTestManager{entries: map[[2]string]string{
				{tc.user, "imap"}:    "192.0.2.21:143",
				{tc.misread, "imap"}: "192.0.2.22:143",
			}}
			configPath := bothSectionsConfig(t, startAffinityAdminAPI(t, am, false))

			out, ok := runAffinityCommand(t, configPath, "get", "--user", tc.user, "--protocol", "imap")
			if !ok || !strings.Contains(out, "Backend: 192.0.2.21:143") {
				t.Errorf("affinity get (exit 0: %v) does not show %s's backend 192.0.2.21:143:\n%s", ok, tc.user, out)
			}

			out, ok = runAffinityCommand(t, configPath, "delete", "--user", tc.user, "--protocol", "imap")
			if !ok {
				t.Fatalf("affinity delete failed:\n%s", out)
			}
			if _, found := am.GetBackend(tc.user, "imap"); found {
				t.Errorf("affinity delete reported success, but %s's affinity is still set:\n%s", tc.user, out)
			}
			if _, found := am.GetBackend(tc.misread, "imap"); !found {
				t.Errorf("affinity delete of %s removed %q's affinity:\n%s", tc.user, tc.misread, out)
			}
		})
	}
}

// `affinity list` lists the node's affinities, optionally of one protocol or backend.
func TestAffinityListCommand(t *testing.T) {
	am := &affinityTestManager{entries: map[[2]string]string{
		{"anna@example.com", "imap"}: "192.0.2.21:143",
		{"anna@example.com", "pop3"}: "192.0.2.21:110",
		{"bob@example.com", "imap"}:  "192.0.2.22:143",
	}}
	configPath := bothSectionsConfig(t, startAffinityAdminAPI(t, am, false))

	// listedLines returns the lines of out that name one of the test's affinities.
	listedLines := func(out string) []string {
		var lines []string
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "@example.com") {
				lines = append(lines, strings.Join(strings.Fields(line), " "))
			}
		}
		return lines
	}

	tests := []struct {
		args []string
		want []string // leading columns of the listed lines: user protocol backend
	}{
		{nil, []string{
			"anna@example.com imap 192.0.2.21:143",
			"anna@example.com pop3 192.0.2.21:110",
			"bob@example.com imap 192.0.2.22:143",
		}},
		{[]string{"--protocol", "pop3"}, []string{"anna@example.com pop3 192.0.2.21:110"}},
		{[]string{"--backend", "192.0.2.22:143"}, []string{"bob@example.com imap 192.0.2.22:143"}},
	}
	for _, tt := range tests {
		t.Run(strings.Join(append([]string{"list"}, tt.args...), " "), func(t *testing.T) {
			out, ok := runAffinityCommand(t, configPath, append([]string{"list"}, tt.args...)...)
			if !ok {
				t.Fatalf("affinity list failed:\n%s", out)
			}
			lines := listedLines(out)
			if len(lines) != len(tt.want) {
				t.Fatalf("affinity list %v listed %d affinities, want %d:\n%s", tt.args, len(lines), len(tt.want), out)
			}
			for i, want := range tt.want {
				if !strings.HasPrefix(lines[i], want+" ") && lines[i] != want {
					t.Errorf("affinity list %v line %d is %q, want it to start with %q:\n%s", tt.args, i, lines[i], want, out)
				}
			}
		})
	}
}
