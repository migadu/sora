//go:build unix

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// sora-admin is usually run as root (sudo), while the server reads and writes its
// fallback directory as its own user (User=sora in dist/sora.service). A certificate
// file root wrote 0600, or a directory root created, is one the server cannot use: with
// S3 unreachable it fails the handshake for a certificate the node holds, and it cannot
// keep the directory up to date (#1308).

// tlsHandOver is one file or directory tls cache gave to another user.
type tlsHandOver struct {
	path     string
	uid, gid int
}

// recordTLSHandOvers makes every directory appear to belong to another user, as the
// server's fallback directory does to root, and records what tls cache gives away
// instead of giving it: only root can.
func recordTLSHandOvers(t *testing.T) *[]tlsHandOver {
	t.Helper()
	realGeteuid, realChown := geteuid, chownFile
	t.Cleanup(func() { geteuid, chownFile = realGeteuid, realChown })
	geteuid = func() int { return os.Geteuid() + 1 }
	var handOvers []tlsHandOver
	chownFile = func(f *os.File, uid, gid int) error {
		handOvers = append(handOvers, tlsHandOver{f.Name(), uid, gid})
		return nil
	}
	return &handOvers
}

func tlsOwner(t *testing.T, path string) tlsHandOver {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return tlsHandOver{path, int(st.Uid), int(st.Gid)}
}

func isTLSCacheTempFile(dir, path string) bool {
	return filepath.Dir(path) == dir && (strings.HasPrefix(filepath.Base(path), ".sora-tls-cache-") || strings.HasPrefix(filepath.Base(path), ".sora-temp-"))
}

// TestTLSCacheGivesNewFilesToTheCacheDirOwner: each certificate tls cache writes into a
// directory that belongs to another user must be given to that user, while it is still
// the temporary file, so the server never sees a cache name it cannot open.
func TestTLSCacheGivesNewFilesToTheCacheDirOwner(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerCertificates(t, cfg, "mail.example.com", "mail.example.com+rsa")
	cacheDir := t.TempDir()
	owner := tlsOwner(t, cacheDir)
	handOvers := recordTLSHandOvers(t)

	if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false); err != nil {
		t.Fatalf("cacheTLSCertificates: %v", err)
	}
	if len(*handOvers) != 2 {
		t.Fatalf("tls cache gave %d files to the cache directory's owner, want 2 (ECDSA and RSA): %+v", len(*handOvers), *handOvers)
	}
	for _, h := range *handOvers {
		if h.uid != owner.uid || h.gid != owner.gid {
			t.Errorf("%s given to %d:%d, want the cache directory's owner %d:%d", h.path, h.uid, h.gid, owner.uid, owner.gid)
		}
		if !isTLSCacheTempFile(cacheDir, h.path) {
			t.Errorf("%s given away, not a temporary file of the cache directory", h.path)
		}
	}
	if got, want := localNames(t, cacheDir), []string{"mail.example.com", "mail.example.com+rsa"}; !slices.Equal(got, want) {
		t.Errorf("local cache = %v, want %v", got, want)
	}
}

// TestTLSCacheForceGivesTheReplacedFileToTheCacheDirOwner: in a directory that belongs
// to another user, the file tls cache --force writes in place of a cached one goes to
// that user, not to the owner of the file it replaces: a file the server does not own,
// such as one an earlier root run left, is one it cannot read, and --force repairs it.
func TestTLSCacheForceGivesTheReplacedFileToTheCacheDirOwner(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerEntry(t, cfg, "mail.example.com", validAutocertEntry(t, "mail.example.com"))
	cacheDir := t.TempDir()
	owner := tlsOwner(t, cacheDir)
	localPath := filepath.Join(cacheDir, "mail.example.com")
	if err := os.WriteFile(localPath, validAutocertEntry(t, "mail.example.com"), 0600); err != nil {
		t.Fatal(err)
	}
	// Only the group of a file can be changed without root: make it another one.
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	otherGID := -1
	for _, gid := range groups {
		if gid != owner.gid {
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
	handOvers := recordTLSHandOvers(t)

	if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", true); err != nil {
		t.Fatalf("cacheTLSCertificates --force: %v", err)
	}
	if len(*handOvers) != 1 {
		t.Fatalf("tls cache --force gave away %d files, want 1: %+v", len(*handOvers), *handOvers)
	}
	if h := (*handOvers)[0]; h.uid != owner.uid || h.gid != owner.gid {
		t.Errorf("the replacement was given to %d:%d, want the cache directory's owner %d:%d, not the replaced file's group %d", h.uid, h.gid, owner.uid, owner.gid, otherGID)
	}
}

// TestTLSCacheKeepsTheFilesInItsOwnCacheDir: run as the owner of the cache directory,
// the server's user or a test, tls cache gives nothing away.
func TestTLSCacheKeepsTheFilesInItsOwnCacheDir(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerCertificates(t, cfg, "mail.example.com", "mail.example.com+rsa")
	cacheDir := filepath.Join(t.TempDir(), "certs")

	realChown := chownFile
	t.Cleanup(func() { chownFile = realChown })
	chownFile = func(f *os.File, uid, gid int) error {
		t.Errorf("tls cache gave %s to %d:%d although this process owns the cache directory", f.Name(), uid, gid)
		return nil
	}

	if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false); err != nil {
		t.Fatalf("cacheTLSCertificates: %v", err)
	}
}

// TestTLSCacheCreatesTheCacheDirLikeTheServer: a cache directory tls cache has to
// create holds private keys and must be made 0700, as the server makes it
// (tlsmanager.NewFallbackCache), with every parent it creates.
func TestTLSCacheCreatesTheCacheDirLikeTheServer(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerCertificates(t, cfg, "mail.example.com")
	stateDir := filepath.Join(t.TempDir(), "state")
	cacheDir := filepath.Join(stateDir, "certs")

	if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false); err != nil {
		t.Fatalf("cacheTLSCertificates: %v", err)
	}
	for _, dir := range []string{stateDir, cacheDir} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0700 {
			t.Errorf("%s created with mode %#o, want 0700", dir, mode)
		}
	}
}

// TestTLSCacheGivesTheCacheDirItCreatesToTheParentsOwner: a directory tls cache creates
// must be given to the owner of the directory it is created in, as the default
// /var/lib/sora/certs goes to the owner of /var/lib/sora, the server's user (the unit's
// StateDirectory). Run as root, a root-owned directory was one the server cannot write
// its certificates to, and the files tls cache wrote into it went to root as well.
func TestTLSCacheGivesTheCacheDirItCreatesToTheParentsOwner(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerCertificates(t, cfg, "mail.example.com", "mail.example.com+rsa")
	top := t.TempDir()
	stateDir := filepath.Join(top, "state")
	cacheDir := filepath.Join(stateDir, "certs")
	handOvers := recordTLSHandOvers(t)

	if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false); err != nil {
		t.Fatalf("cacheTLSCertificates: %v", err)
	}
	// The recorded hand-overs are not made, so each directory still has this user's
	// uid, and the group the system gave it.
	want := []tlsHandOver{tlsOwner(t, top), tlsOwner(t, stateDir), tlsOwner(t, cacheDir), tlsOwner(t, cacheDir)}
	want[0].path, want[1].path = stateDir, cacheDir
	if len(*handOvers) != len(want) {
		t.Fatalf("tls cache gave away %+v, want the two directories it created, then the two certificates", *handOvers)
	}
	for i, h := range *handOvers {
		w := want[i]
		if i >= 2 {
			if !isTLSCacheTempFile(cacheDir, h.path) {
				t.Errorf("hand-over %d is %s, want a certificate of %s", i, h.path, cacheDir)
			}
			w.path = h.path
		}
		if h != w {
			t.Errorf("hand-over %d = %+v, want %+v", i, h, w)
		}
	}
}

// TestTLSCacheGivesACacheDirNamedWithATrailingSlashToTheParentsOwner: fallback_dir =
// "/var/lib/sora/certs/" or --cache-dir with a trailing slash names the same directory,
// whose parent is still /var/lib/sora. filepath.Dir of such a name is the directory
// itself, so tls cache looked up the owner of the directory it had just made: run as
// root that is root, nothing was given away, and the certificates written into it stayed
// root's as well. Here every directory appears to be another user's, so the mistake
// shows as a hand-over of the directory by its unclean name to its own owner.
func TestTLSCacheGivesACacheDirNamedWithATrailingSlashToTheParentsOwner(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerCertificates(t, cfg, "mail.example.com")
	stateDir := t.TempDir()
	cacheDir := filepath.Join(stateDir, "certs")
	handOvers := recordTLSHandOvers(t)

	if err := cacheTLSCertificates(context.Background(), cfg, cacheDir+string(filepath.Separator), "", false); err != nil {
		t.Fatalf("cacheTLSCertificates: %v", err)
	}
	if len(*handOvers) != 2 {
		t.Fatalf("tls cache gave away %+v, want the directory it created, then the certificate", *handOvers)
	}
	if h, w := (*handOvers)[0], tlsOwner(t, stateDir); h.path != cacheDir || h.uid != w.uid || h.gid != w.gid {
		t.Errorf("hand-over 0 = %+v, want %s given to the owner of %s, %d:%d", h, cacheDir, stateDir, w.uid, w.gid)
	}
	if h := (*handOvers)[1]; !isTLSCacheTempFile(cacheDir, h.path) {
		t.Errorf("hand-over 1 is %s, want a certificate of %s", h.path, cacheDir)
	}
}

// TestTLSCacheLeavesADirInASharedParentToItsMaker: in a sticky directory such as /tmp,
// each user's entries are their own, so the directory tls cache creates there is not
// given to the sticky directory's owner (root, for /tmp).
func TestTLSCacheLeavesADirInASharedParentToItsMaker(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerCertificates(t, cfg, "mail.example.com")
	shared := t.TempDir()
	if err := os.Chmod(shared, 0700|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(shared, "certs")
	handOvers := recordTLSHandOvers(t)

	if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false); err != nil {
		t.Fatalf("cacheTLSCertificates: %v", err)
	}
	for _, h := range *handOvers {
		if h.path == cacheDir {
			t.Errorf("tls cache gave %s, created in a sticky directory, to %d:%d", cacheDir, h.uid, h.gid)
		}
	}
}

// TestTLSCacheRemovesTheCacheDirItCannotGiveAway: a directory tls cache created but
// could not give to the owner of its parent is one that owner cannot use; it must be
// removed again and the failure reported.
func TestTLSCacheRemovesTheCacheDirItCannotGiveAway(t *testing.T) {
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerCertificates(t, cfg, "mail.example.com")
	cacheDir := filepath.Join(t.TempDir(), "certs")
	recordTLSHandOvers(t)
	chownFile = func(*os.File, int, int) error { return syscall.EPERM }

	err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("cacheTLSCertificates = %v, want the failure to give %s away", err, cacheDir)
	}
	if !strings.Contains(err.Error(), cacheDir) {
		t.Errorf("error %q does not name %s", err, cacheDir)
	}
	if _, statErr := os.Lstat(cacheDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("%s left behind after it could not be given away (stat: %v)", cacheDir, statErr)
	}
}

// The real hand-over, where it can be made.
func TestTLSCacheAsRootGivesTheCacheToTheServersUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("only root can give a file to another user")
	}
	const nobody = 65534
	_, endpoint := newTLSStubS3(t)
	cfg := tlsTestConfig(endpoint)
	putServerCertificates(t, cfg, "mail.example.com", "mail.example.com+rsa")
	stateDir := t.TempDir()
	if err := os.Chown(stateDir, nobody, nobody); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(stateDir, "certs")

	if err := cacheTLSCertificates(context.Background(), cfg, cacheDir, "", false); err != nil {
		t.Fatalf("cacheTLSCertificates: %v", err)
	}
	for path, mode := range map[string]os.FileMode{
		cacheDir: 0700,
		filepath.Join(cacheDir, "mail.example.com"):     0600,
		filepath.Join(cacheDir, "mail.example.com+rsa"): 0600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st := info.Sys().(*syscall.Stat_t); st.Uid != nobody || st.Gid != nobody {
			t.Errorf("%s belongs to %d:%d, want the state directory's owner %d:%d", path, st.Uid, st.Gid, nobody, nobody)
		}
		if got := info.Mode().Perm(); got != mode {
			t.Errorf("%s has mode %#o, want %#o", path, got, mode)
		}
	}
}

// TestTLSCacheGiveDirDoesNotFollowALink: the user a created directory is given to may
// write its parent and replace the directory with a link; root must not give them the
// link's target.
func TestTLSCacheGiveDirDoesNotFollowALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "certs")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	realChown := chownFile
	t.Cleanup(func() { chownFile = realChown })
	chownFile = func(f *os.File, uid, gid int) error {
		t.Errorf("giveDir gave %s away through a link", f.Name())
		return nil
	}

	parent, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := giveDir(parent, filepath.Base(link), &fileOwner{uid: os.Geteuid(), gid: os.Getegid()}); err == nil {
		t.Error("giveDir succeeded on a symbolic link")
	}
}

// A server-owned ancestor can be replaced after creation but before hand-over.
// Hold the parent directory rather than resolving that ancestor again for chown.
func TestTLSCacheGiveDirDoesNotFollowAnAncestorReplacement(t *testing.T) {
	top := t.TempDir()
	parent := filepath.Join(top, "state")
	outside := filepath.Join(top, "unrelated")
	for _, path := range []string{parent, filepath.Join(outside, "certs")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	untouched, err := os.Stat(filepath.Join(outside, "certs"))
	if err != nil {
		t.Fatal(err)
	}
	realGeteuid, realChown := geteuid, chownFile
	t.Cleanup(func() { geteuid, chownFile = realGeteuid, realChown })
	flipped, gaveCreated := false, false
	geteuid = func() int {
		if !flipped {
			flipped = true
			if err := os.Rename(parent, parent+"-created"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, parent); err != nil {
				t.Fatal(err)
			}
		}
		return os.Geteuid() + 1
	}
	chownFile = func(f *os.File, uid, gid int) error {
		info, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if os.SameFile(info, untouched) {
			t.Error("giveDir gave an unrelated directory away through a replaced ancestor")
		}
		created, err := os.Stat(filepath.Join(parent+"-created", "certs"))
		if err != nil {
			t.Fatal(err)
		}
		gaveCreated = os.SameFile(info, created)
		return nil
	}
	if err := makeCacheDir(filepath.Join(parent, "certs")); err != nil {
		t.Fatal(err)
	}
	if !flipped || !gaveCreated {
		t.Errorf("ancestor replaced=%v, ownership given to the created directory=%v", flipped, gaveCreated)
	}
}

func TestTLSCacheCreatesMissingParentBeforeDotDot(t *testing.T) {
	for _, suffix := range []string{"new/..", "new/../certs"} {
		t.Run(suffix, func(t *testing.T) {
			top := t.TempDir()
			if err := makeCacheDir(top + "/" + suffix); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{filepath.Join(top, "new"), top + "/" + suffix} {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if !info.IsDir() {
					t.Errorf("%s is not a directory", path)
				}
			}
		})
	}
}
