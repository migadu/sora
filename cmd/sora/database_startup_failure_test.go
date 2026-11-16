package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/errors"
)

// unreachableDatabaseConfigEnv names the config a child test process starts its
// services with; the child exits when the database cannot be reached.
const unreachableDatabaseConfigEnv = "SORA_TEST_UNREACHABLE_DATABASE_CONFIG"

// A node that cannot reach its database exits, and the log must say why at a level an
// operator keeps: the reason was logged at INFO, so with level = "warn" or "error" the
// process exited without one (#299).
func TestStartupLogsDatabaseFailureAboveInfo(t *testing.T) {
	if path := os.Getenv(unreachableDatabaseConfigEnv); path != "" {
		eh := errors.NewErrorHandler()
		cfg := config.NewDefaultConfig()
		loadAndValidateConfig(path, &cfg, eh)
		if _, err := logger.Initialize(cfg.Logging); err != nil {
			t.Fatal(err)
		}
		initializeServices(context.Background(), cfg, eh)
		os.Exit(0)
	}

	path := filepath.Join(t.TempDir(), "config.toml")
	// Port 1 on loopback refuses the connection at once. ManageSieve needs the
	// database but not S3, so start-up reaches the database first.
	toml := `
[logging]
output = "stderr"
level = "error"

[database.write]
hosts = ["127.0.0.1"]
port = 1
user = "postgres"
name = "sora_unreachable"

[[server]]
type = "managesieve"
name = "managesieve"
addr = "127.0.0.1:0"
`
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStartupLogsDatabaseFailureAboveInfo$")
	cmd.Env = append(os.Environ(), unreachableDatabaseConfigEnv+"="+path)
	out, err := cmd.CombinedOutput()
	if _, exited := err.(*exec.ExitError); !exited {
		t.Fatalf("start-up with an unreachable database did not fail (err %v):\n%s", err, out)
	}
	if !strings.Contains(string(out), "no healthy database pools available") {
		t.Errorf("with level = \"error\" the log does not say why start-up stopped:\n%s", out)
	}
}
