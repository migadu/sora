//go:build unix

package relayqueue

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func leaseChangeTime(t *testing.T, info os.FileInfo) any {
	t.Helper()
	v := reflect.ValueOf(info.Sys())
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	for _, name := range []string{"Ctim", "Ctimespec", "Ctime"} {
		field := v.FieldByName(name)
		if field.IsValid() {
			return field.Interface()
		}
	}
	t.Fatal("filesystem change-time unavailable")
	return nil
}
func TestLeaseExistingHardlinkIsNotChanged(t *testing.T) {
	q, err := NewDiskQueue(t.TempDir(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "unrelated")
	if err := os.WriteFile(victim, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, filepath.Join(q.processingDir, ".lease-hardlink")); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	real := geteuid
	geteuid = func() int { return os.Geteuid() + 1 }
	defer func() { geteuid = real }()
	// Force the foreign-owner branch without changing any real UID. Even a chown
	// back to the same owner changes ctime; no preexisting inode may be handed over.
	time.Sleep(5 * time.Millisecond)
	lease, err := q.tryLease("hardlink")
	if err != nil || lease == nil {
		t.Fatalf("lease: %v %v", lease, err)
	}
	defer lease.close()
	after, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leaseChangeTime(t, before), leaseChangeTime(t, after)) {
		t.Fatal("acquiring a preexisting hard-link lease changed the unrelated inode")
	}
	if before.Mode() != after.Mode() {
		t.Fatal("unrelated inode mode changed")
	}
	data, err := os.ReadFile(victim)
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("unrelated data: %q %v", data, err)
	}
}
func TestLeaseRejectsUnexpectedModeAndSymlink(t *testing.T) {
	for _, kind := range []string{"mode", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			q, err := NewDiskQueue(t.TempDir(), 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(victim, []byte("keep"), 0644); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(q.processingDir, ".lease-bad")
			if kind == "mode" {
				err = os.Link(victim, path)
			} else {
				err = os.Symlink(victim, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			lease, err := q.tryLease("bad")
			if lease != nil {
				lease.close()
				t.Fatal("unexpected lease admitted")
			}
			if err == nil {
				t.Fatal("unsafe lease had no diagnostic")
			}
			info, err := os.Stat(victim)
			if err != nil || info.Mode().Perm() != 0644 {
				t.Fatalf("victim changed: %v %v", info, err)
			}
		})
	}
}
