package main

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"modernc.org/libc"
	sqlite3 "modernc.org/sqlite/lib"
)

// maildirCacheVFS is the SQLite VFS the maildir cache is opened with: the default one
// (unix), except that the name of a database is used as it is given, which must be
// absolute. The unix VFS resolves every symbolic link in the name before it opens the
// database, and /proc/self/fd/N, the name of a directory descriptor on Linux, is such
// a link, to the directory's path: the cache, its -wal and its -shm would be opened by
// that path again, which the maildir's owner can make lead elsewhere. A name kept as
// it is reaches the directory through the descriptor. SQLite still opens the database
// and the files beside it with O_NOFOLLOW, so a link at one of their names is refused.
const maildirCacheVFS = "sora-maildir"

var registerMaildirCacheVFS = sync.OnceValue(func() error {
	tls := libc.NewTLS()
	defer tls.Close()
	unixVFS := sqlite3.Xsqlite3_vfs_find(tls, 0)
	if unixVFS == 0 {
		return errors.New("SQLite has no default VFS")
	}
	name, err := libc.CString(maildirCacheVFS)
	if err != nil {
		return err
	}
	vfs := sqlite3.Xsqlite3_malloc64(tls, uint64(unsafe.Sizeof(sqlite3.Tsqlite3_vfs{})))
	if vfs == 0 {
		return errors.New("out of memory")
	}
	*sqliteVFSAt(vfs) = *sqliteVFSAt(unixVFS)
	sqliteVFSAt(vfs).FpNext = 0
	sqliteVFSAt(vfs).FzName = name
	sqliteVFSAt(vfs).FxFullPathname = *(*uintptr)(unsafe.Pointer(&struct {
		f func(*libc.TLS, uintptr, uintptr, int32, uintptr) int32
	}{maildirCacheFullPathname}))
	if rc := sqlite3.Xsqlite3_vfs_register(tls, vfs, 0); rc != sqlite3.SQLITE_OK {
		return fmt.Errorf("failed to register SQLite VFS %s: %d", maildirCacheVFS, rc)
	}
	return nil
})

// sqliteVFSAt is the sqlite3_vfs at the address SQLite gave or took.
func sqliteVFSAt(p uintptr) *sqlite3.Tsqlite3_vfs {
	return *(**sqlite3.Tsqlite3_vfs)(unsafe.Pointer(&p))
}

// maildirCacheFullPathname is maildirCacheVFS's xFullPathname: it copies the
// absolute name zName, with its terminating NUL, to the nOut bytes at zOut.
func maildirCacheFullPathname(tls *libc.TLS, pVfs, zName uintptr, nOut int32, zOut uintptr) int32 {
	name := libc.GoString(zName)
	if len(name) == 0 || name[0] != '/' || len(name) >= int(nOut) {
		return sqlite3.SQLITE_CANTOPEN
	}
	out := unsafe.Slice(*(**byte)(unsafe.Pointer(&zOut)), nOut)
	out[copy(out, name)] = 0
	return sqlite3.SQLITE_OK
}
