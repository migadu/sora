package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/errors"
)

const lmtpBackendTOML = `
[[server]]
type = "lmtp"
name = "lmtp"
addr = ":24"
`

const lmtpProxyTOML = `
[[server]]
type = "lmtp_proxy"
name = "lmtp-proxy"
addr = ":2424"
remote_addrs = ["192.0.2.10:24"]
`

// startupConfigEnv names the config a child test process loads with loadAndValidateConfig,
// which exits the process when it refuses the config.
const startupConfigEnv = "SORA_TEST_STARTUP_CONFIG"

// A trusted_networks entry that is neither an IP address nor a CIDR is a config error at
// start-up (#337). It used to start normally, and the LMTP backend and lmtp_proxy then
// dropped the whole list and refused every connection, with the cause logged at debug
// level only.
func TestStartupRefusesMalformedTrustedNetworks(t *testing.T) {
	if path := os.Getenv(startupConfigEnv); path != "" {
		cfg := config.NewDefaultConfig()
		loadAndValidateConfig(path, &cfg, errors.NewErrorHandler())
		os.Exit(0)
	}

	for _, tc := range []struct {
		name     string
		toml     string
		refused  bool
		mentions []string // with refused: what the error names
	}{
		{
			name:     "malformed entry",
			toml:     `[servers]` + "\n" + `trusted_networks = ["192.0.2.0/24", "10.0.0.0/33"]` + "\n" + lmtpBackendTOML,
			refused:  true,
			mentions: []string{"trusted_networks", "10.0.0.0/33"},
		},
		{
			name:     "host name",
			toml:     `[servers]` + "\n" + `trusted_networks = ["mx.example.com"]` + "\n" + lmtpProxyTOML,
			refused:  true,
			mentions: []string{"trusted_networks", "mx.example.com"},
		},
		{
			name:    "IPs and CIDRs",
			toml:    `[servers]` + "\n" + `trusted_networks = ["192.0.2.0/24", "198.51.100.7", "2001:db8::/32", "2001:db8:1::1"]` + "\n" + lmtpBackendTOML + lmtpProxyTOML,
			refused: false,
		},
		{
			name:    "no trusted networks",
			toml:    `[servers]` + "\n" + `trusted_networks = []` + "\n" + lmtpBackendTOML + lmtpProxyTOML,
			refused: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestStartupRefusesMalformedTrustedNetworks$")
			cmd.Env = append(os.Environ(), startupConfigEnv+"="+path)
			out, err := cmd.CombinedOutput()

			if !tc.refused {
				if err != nil {
					t.Fatalf("config refused at start-up (%v):\n%s", err, out)
				}
				return
			}
			if _, exited := err.(*exec.ExitError); !exited {
				t.Fatalf("config accepted at start-up, want it refused (err %v):\n%s", err, out)
			}
			for _, m := range tc.mentions {
				if !strings.Contains(string(out), m) {
					t.Errorf("start-up error does not name %q:\n%s", m, out)
				}
			}
		})
	}
}

// A reload cannot apply trusted_networks (the servers took it at start-up), but a
// malformed entry must be reported as an error, not as an ordinary change: the next
// restart with that file is refused. The running config keeps the start-up networks.
func TestGlobalReloadReportsMalformedTrustedNetworks(t *testing.T) {
	logs := captureReloadLogs(t)
	cfg := startupConfig()
	want := startupConfig()

	handleConfigReload(writeReloadConfig(t, `
[servers]
trusted_networks = ["127.0.0.0/8", "10.0.0.0/33"]
`), &cfg, nil)

	if !slices.Equal(cfg.Servers.TrustedNetworks, want.Servers.TrustedNetworks) {
		t.Errorf("trusted_networks = %v after the reload, want the start-up %v", cfg.Servers.TrustedNetworks, want.Servers.TrustedNetworks)
	}
	if out := logs.String(); !hasLineWith(out, "level=ERROR", "trusted_networks", "10.0.0.0/33") {
		t.Errorf("no error naming the malformed entry 10.0.0.0/33:\n%s", out)
	}
}
