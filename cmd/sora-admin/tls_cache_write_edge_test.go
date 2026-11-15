//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestTLSCacheLongDomainName(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	// Four labels each fit DNS's 63-byte limit; the whole name also fits
	// the existing cache filename, including the RSA variant suffix.
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 50)
	cfg.TLS.LetsEncrypt.Domains = []string{name}
	entry := validAutocertEntry(t, name)
	putServerEntry(t, cfg, name, entry)
	dir := t.TempDir()
	if err := cacheTLSCertificates(context.Background(), cfg, dir, "", false); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, entry) {
		t.Fatal("long domain cache contents differ")
	}
	info, err := os.Stat(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("new cache permissions=%o, want 600", info.Mode().Perm())
	}
}

func TestTLSCacheForceKeepsUnstatableFile(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerEntry(t, cfg, "mail.example.com", validAutocertEntry(t, "mail.example.com"))
	dir := t.TempDir()
	path := filepath.Join(dir, "mail.example.com")
	// Stat cannot resolve this existing directory entry. An atomic write
	// must return that failure, without replacing it or leaving a temp file.
	if err := os.Symlink("mail.example.com", path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("fixture stat=%v, want ELOOP", err)
	}
	if err := cacheTLSCertificates(context.Background(), cfg, dir, "", true); err == nil {
		t.Error("force ignored cache stat failure")
	}
	if target, err := os.Readlink(path); err != nil || target != "mail.example.com" {
		t.Errorf("old entry changed: target=%q err=%v", target, err)
	}
	if names := localNames(t, dir); len(names) != 1 || names[0] != "mail.example.com" {
		t.Errorf("cache after error=%v", names)
	}
}

func TestTLSCacheForceKeepsExistingPermissions(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	entry := validAutocertEntry(t, "mail.example.com")
	putServerEntry(t, cfg, "mail.example.com", entry)
	dir := t.TempDir()
	path := filepath.Join(dir, "mail.example.com")
	// Administrators can make a root-owned cache readable to the server's
	// group. Replacing the file must not discard that existing read permission.
	if err := os.WriteFile(path, []byte("old"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if err := cacheTLSCertificates(context.Background(), cfg, dir, "", true); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf("replacement permissions=%o, want existing 640", info.Mode().Perm())
	}
}
