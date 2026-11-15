//go:build unix

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const tlsCacheWriteHelperEnv = "SORA_ADMIN_TLS_CACHE_WRITE_HELPER"

// TestTLSCacheFailedWriteLeavesNoPartialFile: a write into the local cache that fails
// part-way, as when the disk fills, must leave no partial file under the certificate's
// cache name, where a later run without --force skipped it as already cached and the
// server reads it (#1093). With --force, the certificate cached before must survive.
// The write is made to fail by a file size limit (RLIMIT_FSIZE), which holds for the
// whole process, so the scenario runs in a process of its own.
func TestTLSCacheFailedWriteLeavesNoPartialFile(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestTLSCacheFailedWriteHelper$", "-test.v")
	cmd.Env = append(os.Environ(), tlsCacheWriteHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestTLSCacheFailedWriteHelper") {
		t.Fatalf("helper process failed: %v\n%s", err, out)
	}
}

// TestTLSCacheFailedWriteHelper is not a test: it is the scenario of
// TestTLSCacheFailedWriteLeavesNoPartialFile, run in a process of its own.
func TestTLSCacheFailedWriteHelper(t *testing.T) {
	if os.Getenv(tlsCacheWriteHelperEnv) == "" {
		t.Skip("helper process for TestTLSCacheFailedWriteLeavesNoPartialFile")
	}
	// A write past the limit then fails with EFBIG instead of raising SIGXFSZ.
	signal.Ignore(syscall.SIGXFSZ)
	var unlimited unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &unlimited); err != nil {
		t.Fatal(err)
	}
	// cacheOnFullDisk runs tls cache with every file limited to 64 bytes, a fraction of
	// any certificate.
	cacheOnFullDisk := func(cfg AdminConfig, cacheDir string, force bool) error {
		limited := unlimited
		limited.Cur = 64
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &limited); err != nil {
			t.Fatal(err)
		}
		defer unix.Setrlimit(unix.RLIMIT_FSIZE, &unlimited)
		return cacheTLSCertificates(context.Background(), cfg, cacheDir, "", force)
	}

	t.Run("new", func(t *testing.T) {
		_, endpoint := newTLSStubS3(t)
		cfg := tlsTestConfig(endpoint)
		inS3 := validAutocertEntry(t, "mail.example.com")
		putServerEntry(t, cfg, "mail.example.com", inS3)
		cacheDir := t.TempDir()

		if err := cacheOnFullDisk(cfg, cacheDir, false); err == nil {
			t.Fatal("cacheTLSCertificates succeeded although the write failed")
		}
		if names := localNames(t, cacheDir); len(names) > 0 {
			t.Errorf("the failed write left %v in the local cache", names)
		}

		// With room on the disk again, the next run caches the certificate.
		if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false); err != nil {
			t.Fatalf("cacheTLSCertificates: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(cacheDir, "mail.example.com"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, inS3) {
			t.Errorf("local cache holds %d bytes, not the certificate from S3 (%d bytes)", len(got), len(inS3))
		}
	})

	t.Run("force", func(t *testing.T) {
		_, endpoint := newTLSStubS3(t)
		cfg := tlsTestConfig(endpoint)
		putServerEntry(t, cfg, "mail.example.com", validAutocertEntry(t, "mail.example.com"))
		cacheDir := t.TempDir()
		cached := validAutocertEntry(t, "mail.example.com")
		localPath := filepath.Join(cacheDir, "mail.example.com")
		if err := os.WriteFile(localPath, cached, 0600); err != nil {
			t.Fatal(err)
		}

		if err := cacheOnFullDisk(cfg, cacheDir, true); err == nil {
			t.Fatal("cacheTLSCertificates --force succeeded although the write failed")
		}
		got, err := os.ReadFile(localPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, cached) {
			t.Errorf("the failed write left %d bytes of the cached certificate (%d bytes)", len(got), len(cached))
		}
		if names, want := localNames(t, cacheDir), []string{"mail.example.com"}; !slices.Equal(names, want) {
			t.Errorf("local cache = %v, want %v", names, want)
		}
	})
}

// TestTLSCacheForceKeepsTheOwnerOfTheReplacedFile: the file tls cache --force writes in
// place of a cached one must have that file's owner, so that, run as root, it leaves the
// server a file it can read. A user who is not root can change only the group, so the
// test gives the cached file another of the user's groups.
func TestTLSCacheForceKeepsTheOwnerOfTheReplacedFile(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	inS3 := validAutocertEntry(t, "mail.example.com")
	putServerEntry(t, cfg, "mail.example.com", inS3)
	cacheDir := t.TempDir()
	localPath := filepath.Join(cacheDir, "mail.example.com")
	if err := os.WriteFile(localPath, validAutocertEntry(t, "mail.example.com"), 0600); err != nil {
		t.Fatal(err)
	}

	// A new file in cacheDir gets the group the cached file now has; give it another.
	newGID := fileGID(t, localPath)
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	otherGID := -1
	for _, gid := range groups {
		if gid != newGID {
			otherGID = gid
			break
		}
	}
	if otherGID < 0 {
		t.Skip("the user is in no other group to give the cached file")
	}
	if err := os.Chown(localPath, -1, otherGID); err != nil {
		t.Fatal(err)
	}

	if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", true); err != nil {
		t.Fatalf("cacheTLSCertificates --force: %v", err)
	}
	got, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, inS3) {
		t.Error("--force did not replace the cached certificate with the one from S3")
	}
	if gid := fileGID(t, localPath); gid != otherGID {
		t.Errorf("the replaced file has group %d, want the cached file's group %d", gid, otherGID)
	}
}

func fileGID(t *testing.T, path string) int {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return int(info.Sys().(*syscall.Stat_t).Gid)
}
