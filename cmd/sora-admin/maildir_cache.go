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
func openMaildirCache(dir string) (*sql.DB, error) {
	// SQLite names the database by its absolute path with every link resolved, and
	// the files beside it are checked in that resolved directory.
	dir, err := resolveMaildirDir(dir)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{maildirCacheName, maildirCacheName + "-wal", maildirCacheName + "-shm", maildirCacheName + "-journal"} {
		if info, err := os.Lstat(filepath.Join(dir, name)); err == nil && !info.Mode().IsRegular() {
			return nil, notRegularMaildirCache(filepath.Join(dir, name), info)
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
	if !info.Mode().IsRegular() {
		return nil, notRegularMaildirCache(path, info)
	}

	return openMaildirCacheFile(path)
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
