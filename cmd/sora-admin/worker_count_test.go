package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestImportExportRejectWorkerCountBelowOne (#1404): the S3 importer, the maildir
// importer and the maildir exporter run their work on as many goroutines as they are
// given. With none, `import s3` hung once its queue filled (and below that reported a
// run that processed nothing), `import maildir` hung at its first file or panicked
// creating its queue, and `export maildir` succeeded having written nothing. A count
// below 1 is refused before anything is created.
func TestImportExportRejectWorkerCountBelowOne(t *testing.T) {
	ctx := context.Background()
	for _, n := range []int{0, -1} {
		t.Run(fmt.Sprintf("import s3 workers %d", n), func(t *testing.T) {
			tmpDir := t.TempDir()
			t.Setenv("TMPDIR", tmpDir)
			si, err := NewS3Importer(ctx, nil, nil, S3ImporterOptions{Email: "user@example.com", Workers: n, CleanupDB: true})
			if err == nil {
				si.Close()
				t.Fatalf("NewS3Importer accepted Workers: %d", n)
			}
			if names := dirNames(t, tmpDir); len(names) != 0 {
				t.Errorf("the refused importer left %v in TMPDIR", names)
			}
		})
		t.Run(fmt.Sprintf("import maildir jobs %d", n), func(t *testing.T) {
			maildir := t.TempDir()
			importer, err := NewImporter(ctx, maildir, "user@example.com", n, nil, nil, ImporterOptions{TestMode: true})
			if err == nil {
				importer.Close()
				t.Fatalf("NewImporter accepted jobs %d", n)
			}
			if names := dirNames(t, maildir); len(names) != 0 {
				t.Errorf("the refused importer left %v in the maildir", names)
			}
		})
		t.Run(fmt.Sprintf("export maildir jobs %d", n), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "Maildir")
			exporter, err := NewExporter(ctx, out, "user@example.com", n, nil, nil, ExporterOptions{})
			if err == nil {
				exporter.Close()
				t.Fatalf("NewExporter accepted jobs %d", n)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Errorf("the refused exporter created %s (stat: %v)", out, err)
			}
		})
	}
}

// TestImportExportFlagsRejectWorkerCountBelowOne (#1404): `import s3 --workers`,
// `import maildir --jobs` and `export maildir --jobs` below 1 are flag errors, reported
// before the command connects to the database or S3.
func TestImportExportFlagsRejectWorkerCountBelowOne(t *testing.T) {
	// A database nothing listens on: a command that gets past its flags fails to connect.
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, []byte("[database.write]\nhosts = [\"127.0.0.1\"]\nport = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, -1} {
		maildir := t.TempDir()
		for _, tc := range []struct {
			name string
			args []string
			want string
		}{
			{"import s3", []string{"import", "s3", "--email", "user@example.com", "--workers", strconv.Itoa(n)}, "--workers must be at least 1"},
			{"import maildir", []string{"import", "maildir", "--email", "user@example.com", "--maildir-path", maildir, "--jobs", strconv.Itoa(n)}, "--jobs must be at least 1"},
			{"export maildir", []string{"export", "maildir", "--email", "user@example.com", "--maildir-path", filepath.Join(maildir, "out"), "--jobs", strconv.Itoa(n)}, "--jobs must be at least 1"},
		} {
			t.Run(fmt.Sprintf("%s %d", tc.name, n), func(t *testing.T) {
				out, code := runAdminMain(t, append([]string{"--config", configPath}, tc.args...)...)
				if code == 0 {
					t.Fatalf("exit code 0, want non-zero:\n%s", out)
				}
				if !strings.Contains(out, tc.want) {
					t.Errorf("output lacks %q:\n%s", tc.want, out)
				}
				if strings.Contains(out, "write pool") {
					t.Errorf("the command got past its flags:\n%s", out)
				}
			})
		}
	}
}

// TestImportMaildirFlagRejectsBatchSizeBelowOne: `import maildir --batch-size` below 1 is a
// flag error like --jobs, reported before the command connects to the database.
func TestImportMaildirFlagRejectsBatchSizeBelowOne(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, []byte("[database.write]\nhosts = [\"127.0.0.1\"]\nport = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, -1} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			out, code := runAdminMain(t, "--config", configPath, "import", "maildir", "--email", "user@example.com",
				"--maildir-path", t.TempDir(), "--batch-size", strconv.Itoa(n))
			if code == 0 {
				t.Fatalf("exit code 0, want non-zero:\n%s", out)
			}
			if !strings.Contains(out, "--batch-size must be at least 1") {
				t.Errorf("output lacks %q:\n%s", "--batch-size must be at least 1", out)
			}
			if strings.Contains(out, "write pool") {
				t.Errorf("the command got past its flags:\n%s", out)
			}
		})
	}
}

// TestImporterBatchSizeBelowOneUsesTheDefault: NewImporter takes a batch size below 1 for
// the default of 20, but importMessages read the option again and handed -1 to make(), so
// an import with a negative batch size panicked at its first batch.
func TestImporterBatchSizeBelowOneUsesTheDefault(t *testing.T) {
	for _, n := range []int{0, -1} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			importer, err := NewImporter(context.Background(), newCleanupDBMaildir(t, 2), "user@example.com", 1, nil, nil,
				ImporterOptions{TestMode: true, BatchSize: n})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { importer.Close() })
			importer.rdb = newMockResilientDatabase()

			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("import with batch size %d panicked: %v", n, p)
					}
				}()
				if err := importer.Run(); err != nil {
					t.Fatalf("import with batch size %d: %v", n, err)
				}
			}()
			if importer.importedMessages != 2 {
				t.Errorf("imported %d messages, want 2", importer.importedMessages)
			}
			if importer.batchSize != 20 {
				t.Errorf("batch size %d, want the default 20", importer.batchSize)
			}
		})
	}
}
