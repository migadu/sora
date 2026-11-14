package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigValidateChecksTrustedNetworks(t *testing.T) {
	for _, tc := range []struct{ name, networks, want string }{
		{"malformed CIDR", `["127.0.0.1", "10.0.0.0/33"]`, "10.0.0.0/33"},
		{"hostname", `["mailrelay.example"]`, "mailrelay.example"},
		{"valid", `["127.0.0.1", "::1", "10.0.0.0/8"]`, ""},
		{"empty", `[]`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			body := fmt.Sprintf("[servers]\ntrusted_networks = %s\n[[server]]\ntype = \"lmtp\"\nname = \"lmtp\"\naddr = \"127.0.0.1:0\"\n", tc.networks)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestConfigValidateCommandHelper$")
			cmd.Env = append(os.Environ(), configValidateHelperEnv+"="+path)
			output, err := cmd.CombinedOutput()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("valid trusted_networks refused: %v\n%s", err, output)
				}
			} else if err == nil || !strings.Contains(string(output), tc.want) {
				t.Fatalf("invalid trusted_networks: err=%v, want error naming %s\n%s", err, tc.want, output)
			}
		})
	}
}
