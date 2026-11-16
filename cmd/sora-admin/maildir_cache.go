package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/migadu/sora/pkg/sqlitefile"
	"modernc.org/sqlite"
)

// maildirCacheName is the import and export cache database, in the maildir.
const maildirCacheName = "sora-maildir.db"

// maildirCacheSettings are the connection settings of sora-maildir.db, for import and
// export alike: WAL lets readers and the writer work concurrently, and a locked
// database is waited for up to 5 seconds. The busy timeout comes first: the switch to
// WAL needs the database lock, which another process may hold.
const maildirCacheSettings = `PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL`

// hardLinksProtected reports whether this system forbids a user to hard-link a file
// they neither own nor may read and write: Linux with fs.protected_hardlinks = 1, the
// default of most distributions. macOS and FreeBSD (by default) allow it. A variable,
// so tests can turn the protection off.
var hardLinksProtected = func() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	setting, err := os.ReadFile("/proc/sys/fs/protected_hardlinks")
	return err == nil && strings.TrimSpace(string(setting)) == "1"
}

// openMaildirCache opens sora-maildir.db in dir (the maildir of an import, the
// destination of an export), creating it if it is missing. dir is the operator's
// choice, but its owner may be able to write in it, and import and export often run
// as root. SQLite follows a symbolic link at the database's name, creates or writes
// the file it names, and keeps the -wal, -shm and -journal files next to that file,
// so the owner could have the cache created or written anywhere (#1606). The cache
// and those three files must be regular files where they exist, and anything else is
// refused, naming it.
//
// The open is race-free, for an import in place while the owner can still write:
// the file is created or opened here without following a link and checked to be a
// regular file; SQLite then opens it without creating it (mode=rw), and every
// connection is checked before cache settings are applied, to have opened it by
// the name it was given and not through a link. Opening a connection can already
// read the database header before that identity check. SQLite resolves
// links only in the name of the database (and then names the file by the link's
// target); it opens the database and its -wal, -shm and -journal files with
// O_NOFOLLOW. dir itself is trusted, as for the rest of the import.
//
// A hard link at one of the four names is a regular file, and SQLite writes through
// it: the WAL index into -shm on every run, WAL frames into -wal, the cache into
// sora-maildir.db (#1669). No check of the files can be race-free here, since SQLite
// opens -wal and -shm by name after any check, so maildirCacheLinkRule allows the
// cache only in a directory where no other user can put such a link to a file they
// could not write themselves.
func openMaildirCache(dir string) (*sql.DB, error) {
	// SQLite names the database by its absolute path with every link resolved, and
	// the files beside it are checked in that resolved directory.
	dir, err := resolveMaildirDir(dir)
	if err != nil {
		return nil, err
	}
	refuseHardLinks, err := maildirCacheLinkRule(dir)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{maildirCacheName, maildirCacheName + "-wal", maildirCacheName + "-shm", maildirCacheName + "-journal"} {
		if info, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			if err := checkMaildirCacheFile(filepath.Join(dir, name), info, refuseHardLinks); err != nil {
				return nil, err
			}
		}
	}
	path := filepath.Join(dir, maildirCacheName)

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open maildir database: %w", err)
	}
	info, err := f.Stat()
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to open maildir database: %w", err)
	}
	if err := checkMaildirCacheFile(path, info, refuseHardLinks); err != nil {
		return nil, err
	}

	return openMaildirCacheFile(path)
}

// maildirCacheLinkRule decides where the cache may be kept against hard links. On a
// system that lets a user hard-link only a file they own or may read and write, such
// a link can only make the run write a file whoever put it there could write
// themselves, and any directory will do. Elsewhere dir must belong to the user this
// process runs as, with no group or other write permission (access control lists are
// not read): then nobody else can put a link in it while the run starts, and one that
// is already there (left from before the directory was that user's alone, or linked
// to a backup) is refused, as refuseHardLinks says. A directory other users can write
// is refused.
//
// dir is checked by its name, and SQLite opens the files by that name later, so the
// directories above dir are checked too: a user who could rename an entry in one of
// them could put a directory of their own, holding such links, at dir's name after
// the checks. Each must belong to root or to this user, and others may write in it
// only where the sticky bit keeps them from renaming an entry they do not own (as in
// /tmp): no other user can then change what dir names.
func maildirCacheLinkRule(dir string) (refuseHardLinks bool, err error) {
	if hardLinksProtected() {
		return false, nil
	}
	euid := geteuid()
	var parents []string
	for parent := filepath.Dir(dir); ; parent = filepath.Dir(parent) {
		parents = append(parents, parent)
		if parent == filepath.Dir(parent) {
			break
		}
	}
	// Check from the filesystem root towards dir. Each accepted component then
	// protects the next name from another user's rename. Lstat below refuses a
	// symbolic link introduced after resolveMaildirDir, even to a trusted target.
	for index := len(parents) - 1; index >= 0; index-- {
		parent := parents[index]
		owner, mode, err := directoryOwnerAndMode(parent)
		if err != nil {
			return false, err
		}
		if (owner != 0 && owner != euid) || (mode&0o022 != 0 && mode&syscall.S_ISVTX == 0) {
			return false, fmt.Errorf("refusing to keep the maildir database in %s: users other than uid %d can rename entries of %s above it (owner uid %d, mode %04o), and so put a directory of their own, with hard links at the database's names, in its place after it is checked; use a directory whose parents only root and uid %d can write", dir, euid, parent, owner, mode, euid)
		}
	}
	owner, mode, err := directoryOwnerAndMode(dir)
	if err != nil {
		return false, err
	}
	if owner != euid || mode&0o022 != 0 {
		return false, fmt.Errorf("refusing to keep the maildir database in %s: users other than uid %d can create files in it (owner uid %d, mode %04o), and SQLite would write through a hard link one of them puts at the database's names; run as the directory's owner, or use a directory only uid %d can write", dir, euid, owner, mode, euid)
	}
	return true, nil
}

// directoryOwnerAndMode returns the owner of the directory at path and its permission
// bits, with the set-user-ID, set-group-ID and sticky bits. It is replaceable in
// tests to schedule a directory pivot around a real metadata read.
var directoryOwnerAndMode = func(path string) (owner int, mode uint32, err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to check maildir database directory: %w", err)
	}
	if !info.IsDir() {
		return 0, 0, fmt.Errorf("refusing maildir database directory %s: it is not a directory", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("failed to check maildir database directory %s: no owner", path)
	}
	return int(st.Uid), uint32(st.Mode) & 0o7777, nil
}

// checkMaildirCacheFile refuses the maildir cache, or one of the files SQLite keeps
// beside it, at path when info shows it is not a regular file or, with
// refuseHardLinks, when the file has another name too.
func checkMaildirCacheFile(path string, info fs.FileInfo, refuseHardLinks bool) error {
	if !info.Mode().IsRegular() {
		return notRegularMaildirCache(path, info)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && refuseHardLinks && st.Nlink > 1 {
		return fmt.Errorf("refusing maildir database file %s: it is a hard link, one of %d names of its file", path, st.Nlink)
	}
	return nil
}

// resolveMaildirDir returns the absolute path of dir with every symbolic link
// resolved. A relative dir is not cleaned (as filepath.Abs would): a ".." after a
// link is resolved from the link's target, as the OS does.
func resolveMaildirDir(dir string) (string, error) {
	if !filepath.IsAbs(dir) {
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to resolve maildir database directory: %w", err)
		}
		dir = wd + string(filepath.Separator) + dir
	}
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve maildir database directory: %w", err)
	}
	return dir, nil
}

// effectiveMaildirPath keeps maildirPath when filepath.Clean(maildirPath) names the
// same directory (including when maildirPath is itself a symbolic link to a
// maildir), and otherwise returns the OS-resolved directory so os.OpenRoot,
// filepath.Clean, and filepath.Join do not collapse a ".." across a symbolic link
// onto a different or missing directory.
func effectiveMaildirPath(maildirPath string) string {
	info, err := os.Stat(maildirPath)
	if err != nil {
		return maildirPath
	}
	if cleanInfo, err := os.Stat(filepath.Clean(maildirPath)); err == nil && os.SameFile(info, cleanInfo) {
		return maildirPath
	}
	resolved, err := resolveMaildirDir(maildirPath)
	if err != nil {
		return maildirPath
	}
	return resolved
}

// openMaildirCacheFile opens the maildir cache at path, an absolute name with no
// link in it, which must exist.
func openMaildirCacheFile(path string) (*sql.DB, error) {
	dsn, err := sqlitefile.DSN(path, "mode=rw")
	if err != nil {
		return nil, err
	}
	connector, err := sqlite.NewConnector(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}
	db := sql.OpenDB(maildirCacheConnector{Connector: connector, path: path})
	// SQLite works best with a single writer connection.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

// maildirCacheConnector opens the connections to the maildir cache at path: it
// refuses one that SQLite opened through a link, and applies the connection settings.
type maildirCacheConnector struct {
	driver.Connector
	path string
}

func (c maildirCacheConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.setUp(ctx, conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c maildirCacheConnector) setUp(ctx context.Context, conn driver.Conn) error {
	db, ok := conn.(sqlite.ExecQuerierContext)
	if !ok {
		return fmt.Errorf("unexpected SQLite connection %T", conn)
	}
	// PRAGMA database_list reads nothing from the file, unlike a statement that needs
	// the schema (which could, for one, roll a hot journal back into it).
	rows, err := db.QueryContext(ctx, "PRAGMA database_list", nil)
	if err != nil {
		return fmt.Errorf("failed to check maildir database: %w", err)
	}
	file, err := mainDatabaseFile(rows)
	if err != nil {
		return fmt.Errorf("failed to check maildir database: %w", err)
	}
	if file != c.path {
		return fmt.Errorf("refusing maildir database %s: SQLite opened %s, through a symbolic link", c.path, file)
	}
	if _, err := db.ExecContext(ctx, maildirCacheSettings, nil); err != nil {
		return fmt.Errorf("failed to configure maildir database: %w", err)
	}
	return nil
}

// mainDatabaseFile returns the file of the main database from the rows of PRAGMA
// database_list (seq, name, file), and closes them.
func mainDatabaseFile(rows driver.Rows) (string, error) {
	defer rows.Close()
	row := make([]driver.Value, len(rows.Columns()))
	for {
		if err := rows.Next(row); err == io.EOF {
			return "", errors.New("no main database")
		} else if err != nil {
			return "", err
		}
		if name, _ := row[1].(string); name == "main" {
			file, _ := row[2].(string)
			return file, nil
		}
	}
}

// notRegularMaildirCache is the refusal of the maildir cache, or one of the files
// SQLite keeps beside it, at path: info shows it is not a regular file.
func notRegularMaildirCache(path string, info fs.FileInfo) error {
	what := "not a regular file"
	if info.Mode()&fs.ModeSymlink != 0 {
		what = "a symbolic link"
	}
	return fmt.Errorf("refusing maildir database file %s: it is %s", path, what)
}
