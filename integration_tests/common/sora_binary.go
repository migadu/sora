//go:build integration

package common

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

var (
	soraBinaryOnce sync.Once
	soraBinaryPath string
)

// GetSoraBinary returns the absolute path to the sora server binary, for tests that start a
// whole node from a configuration file and drive it from the outside.
//
// Like GetSoraAdminBinary, the binary is always rebuilt from the current working tree (a
// no-op rebuild costs well under a second thanks to the build cache) so a test can never
// silently run a stale binary from another branch. Set SORA_BIN to use a prebuilt one.
func GetSoraBinary(t testing.TB) string {
	if t != nil {
		t.Helper()
	}
	soraBinaryOnce.Do(func() {
		if envBin := os.Getenv("SORA_BIN"); envBin != "" {
			if _, err := os.Stat(envBin); err == nil {
				soraBinaryPath = envBin
				return
			}
		}

		repoRoot, err := FindRepoRoot()
		if err != nil {
			if t != nil {
				t.Fatalf("Failed to locate repo root for sora: %v", err)
			}
			panic(err)
		}

		// Build to a process-private path, then rename into place: several test packages
		// may run concurrently, and rename is atomic.
		targetBin := filepath.Join(repoRoot, "integration_tests", "sora")
		tmpBin := fmt.Sprintf("%s.build-%d", targetBin, os.Getpid())
		cmd := exec.Command("go", "build", "-o", tmpBin, "./cmd/sora")
		cmd.Dir = repoRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			os.Remove(tmpBin)
			if t != nil {
				t.Fatalf("Failed to build sora at %s: %v\nOutput: %s", targetBin, err, string(out))
			}
			panic(fmt.Sprintf("Failed to build sora: %v: %s", err, string(out)))
		}
		if err := os.Rename(tmpBin, targetBin); err != nil {
			os.Remove(tmpBin)
			if t != nil {
				t.Fatalf("Failed to install sora at %s: %v", targetBin, err)
			}
			panic(fmt.Sprintf("Failed to install sora at %s: %v", targetBin, err))
		}
		soraBinaryPath = targetBin
	})

	if soraBinaryPath == "" {
		if t != nil {
			t.Fatalf("sora binary not available")
		}
		panic("sora binary not available")
	}
	return soraBinaryPath
}
