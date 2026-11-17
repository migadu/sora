package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Keep the directory spelling until the checked root walk: cleaning first erases
// the link and can select another script before the policy sees it.
func TestReadSieveFileChecksRootLinkBeforeDotDot(t *testing.T) {
	for _, foreign := range []bool{true, false} {
		t.Run(map[bool]string{true: "foreign link refused", false: "running user link follows OS path"}[foreign], func(t *testing.T) {
			alice, bob := t.TempDir(), t.TempDir()
			require.NoError(t, os.Mkdir(filepath.Join(bob, "deep"), 0700))
			require.NoError(t, os.WriteFile(filepath.Join(alice, "main.sieve"), []byte("keep;"), 0444))
			require.NoError(t, os.WriteFile(filepath.Join(bob, "main.sieve"), []byte("discard;"), 0444))
			require.NoError(t, os.Symlink(filepath.Join(bob, "deep"), filepath.Join(alice, "pivot")))
			original := fileUID
			t.Cleanup(func() { fileUID = original })
			fileUID = func(info os.FileInfo) uint32 {
				if foreign && info.Name() == "pivot" {
					return uint32(os.Geteuid() + 1)
				}
				return original(info)
			}
			path := alice + string(filepath.Separator) + "pivot" + string(filepath.Separator) + ".." + string(filepath.Separator) + "main.sieve"
			got, err := readSieveFile(path)
			if foreign {
				require.ErrorContains(t, err, "symbolic link")
				require.Nil(t, got)
			} else {
				require.NoError(t, err)
				require.Equal(t, "discard;", string(got))
			}
		})
	}
}
