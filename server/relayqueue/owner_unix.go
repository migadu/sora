//go:build unix

package relayqueue

import (
	"os"
	"syscall"
)

// geteuid is os.Geteuid. Only root can give a file to another user, so tests replace
// it to reach that path.
var geteuid = os.Geteuid

// foreignOwner returns the owner of dir when that is not the user this process runs
// as, and nil when it is.
func foreignOwner(dir string) (*fileOwner, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) == geteuid() {
		return nil, nil
	}
	return &fileOwner{uid: int(st.Uid), gid: int(st.Gid)}, nil
}
