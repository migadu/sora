package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestVerifyAndMigrateFlagsRejectCountBelowOne (#1553): `verify s3 --batch-size` stepped its
// loop by the value (0 spun forever once the account had a message, -1 panicked slicing
// messages[0:-1]) and `migrate down --limit` handed its negation to golang-migrate's Steps
// (0 failed with a bare "no change", -1 applied the next migration up). A value below 1 is
// a flag error, reported before the command connects to the database or S3.
func TestVerifyAndMigrateFlagsRejectCountBelowOne(t *testing.T) {
	// A database nothing listens on: a command that gets past its flags fails to connect.
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, []byte("[database.write]\nhosts = [\"127.0.0.1\"]\nport = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, -1} {
		for _, tc := range []struct {
			name      string
			args      []string
			want      string
			connected string // what the command prints once it has tried the database
		}{
			{"verify s3 --batch-size", []string{"verify", "s3", "--email", "user@example.com", "--batch-size", strconv.Itoa(n)},
				"--batch-size must be at least 1", "failed to initialize database"},
			{"migrate down --limit", []string{"migrate", "down", "--limit", strconv.Itoa(n)},
				"--limit must be at least 1", "Failed to initialize migration tool"},
		} {
			t.Run(tc.name+" "+strconv.Itoa(n), func(t *testing.T) {
				out, code := runAdminMain(t, append([]string{"--config", configPath}, tc.args...)...)
				if code == 0 {
					t.Fatalf("exit code 0, want non-zero:\n%s", out)
				}
				if !strings.Contains(out, tc.want) {
					t.Errorf("output lacks %q:\n%s", tc.want, out)
				}
				if strings.Contains(out, tc.connected) {
					t.Errorf("the command got past its flags:\n%s", out)
				}
			})
		}
	}
}

// TestCheckDBToS3RejectsBatchSizeBelowOne (#1553): checkDBToS3 steps through the account's
// messages by batchSize, so a caller other than the CLI passing 0 would loop forever and a
// negative size would panic. It refuses such a size before reading anything.
func TestCheckDBToS3RejectsBatchSizeBelowOne(t *testing.T) {
	for _, n := range []int{0, -1} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			var err error
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("checkDBToS3 with batch size %d got past its argument check: %v", n, p)
					}
				}()
				// No database and no S3: the size must be refused before either is used.
				err = checkDBToS3(context.Background(), nil, nil, 1, &verificationResult{}, n, false)
			}()
			if err == nil || !strings.Contains(err.Error(), "batch size") {
				t.Fatalf("checkDBToS3 with batch size %d returned %v, want a batch size error", n, err)
			}
		})
	}
}
