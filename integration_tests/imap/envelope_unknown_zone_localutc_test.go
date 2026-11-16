//go:build integration

package imap_test

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// Keep Local's pointer change in a subprocess so active test servers and
// database goroutines never observe a concurrent global configuration change.
func TestIMAP_EnvelopeDateUnknownZoneLocalUTC(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	const childEnv = "SORA_TEST_ENVELOPE_UNKNOWN_ZONE_LOCAL_UTC"
	if os.Getenv(childEnv) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestIMAP_EnvelopeDateUnknownZoneLocalUTC$", "-test.count=1", "-test.timeout=2m")
		cmd.Env = append(os.Environ(), childEnv+"=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Local=UTC wire controls failed: %v\n%s", err, output)
		}
		return
	}
	time.Local = time.UTC
	t.Run("top-level envelope", TestIMAP_EnvelopeDateObsoleteZone)
	t.Run("cached attached envelope", TestIMAP_BodyStructureAttachedEnvelopeDateObsoleteZone)
}
