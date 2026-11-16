//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// An export merges into what its destination already holds (dovecot-keywords,
// dovecot-uidlist and the cur/ and new/ directories it names files in), so it may be
// given a maildir its owner could write to. The owner can leave a FIFO at any of those
// names, and opening a FIFO for reading blocks until something opens it for writing:
// the export never finished (#1630). This is the export's side of #1608.

// returnsDespiteFIFO makes path a FIFO, runs call and fails the test unless call
// returns within a few seconds; it returns call's error.
func returnsDespiteFIFO(t *testing.T, path string, call func() error) error {
	t.Helper()
	require.NoError(t, unix.Mkfifo(path, 0o644))
	done := make(chan error, 1)
	go func() { done <- call() }()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatalf("the export blocked on the FIFO at %s", path)
		return nil
	}
}

func TestExportDoesNotBlockOnFIFODovecotKeywords(t *testing.T) {
	exporter, dest := newLinkTestExporter(t, nil, ExporterOptions{Dovecot: true})
	keywords := filepath.Join(dest, "dovecot-keywords")

	err := returnsDespiteFIFO(t, keywords, func() error {
		return exporter.prepareKeywords("INBOX", []db.Message{{UID: 1, CustomFlags: []string{"$Work"}}})
	})

	// A FIFO names no keywords to keep: it is replaced like a file that cannot be read.
	require.NoError(t, err)
	assertRegularFile(t, keywords)
	got, err := os.ReadFile(keywords)
	require.NoError(t, err)
	assert.Equal(t, "0 $Work\n", string(got))
}

// A regular dovecot-keywords an earlier run left is still read: the numbering it gives
// is kept, so files that run wrote keep their meaning.
func TestExportKeepsExistingDovecotKeywordsNumbering(t *testing.T) {
	exporter, dest := newLinkTestExporter(t, nil, ExporterOptions{Dovecot: true})
	keywords := filepath.Join(dest, "dovecot-keywords")
	require.NoError(t, os.WriteFile(keywords, []byte("3 $Old\n"), 0o644))

	require.NoError(t, exporter.prepareKeywords("INBOX", []db.Message{{UID: 1, CustomFlags: []string{"$Old", "$Work"}}}))

	got, err := os.ReadFile(keywords)
	require.NoError(t, err)
	assert.Equal(t, "0 $Work\n3 $Old\n", string(got))
}

func TestExportDoesNotBlockOnFIFODovecotUIDList(t *testing.T) {
	exporter, dest := newLinkTestExporter(t, nil, ExporterOptions{ExportUIDList: true})
	uidlist := filepath.Join(dest, "dovecot-uidlist")
	exporter.uidMappings["INBOX"] = []UIDFileMapping{{UID: 7, Filename: "1700000001.M1P1.host"}}

	err := returnsDespiteFIFO(t, uidlist, func() error {
		return exporter.generateDovecotUIDLists([]*db.DBMailbox{{Name: "INBOX", UIDValidity: 42}})
	})

	// A FIFO names no UIDs to keep: it is replaced like a file that cannot be read.
	require.NoError(t, err)
	assertRegularFile(t, uidlist)
	written, err := ParseDovecotUIDList(dest)
	require.NoError(t, err)
	require.NotNil(t, written)
	assert.Equal(t, uint32(42), written.UIDValidity)
	assert.Equal(t, map[string]uint32{"1700000001.M1P1.host": 7}, written.UIDMappings)
}

// The merge with an earlier run's dovecot-uidlist lists cur/ and new/ to keep the
// entries whose file is still there. The owner can replace either directory with a FIFO
// once the export has created it, at any time before the uidlist is written at the end.
func TestExportDoesNotBlockOnFIFOMaildirDirectory(t *testing.T) {
	for _, sub := range []string{"cur", "new"} {
		t.Run(sub, func(t *testing.T) {
			exporter, dest := newLinkTestExporter(t, nil, ExporterOptions{ExportUIDList: true})
			other := map[string]string{"cur": "new", "new": "cur"}[sub]
			require.NoError(t, os.WriteFile(filepath.Join(dest, other, "1600000000.M1P1.host"), []byte(linkTestMessageBody), 0o644))
			require.NoError(t, os.WriteFile(filepath.Join(dest, "dovecot-uidlist"), []byte("3 V42 N4\n3 :1600000000.M1P1.host\n"), 0o644))
			require.NoError(t, os.Remove(filepath.Join(dest, sub)))
			exporter.uidMappings["INBOX"] = []UIDFileMapping{{UID: 7, Filename: "1700000001.M1P1.host"}}

			err := returnsDespiteFIFO(t, filepath.Join(dest, sub), func() error {
				return exporter.generateDovecotUIDLists([]*db.DBMailbox{{Name: "INBOX", UIDValidity: 42}})
			})

			// The FIFO holds no message files; the earlier entry whose file is in the
			// other directory is kept.
			require.NoError(t, err)
			written, err := ParseDovecotUIDList(dest)
			require.NoError(t, err)
			require.NotNil(t, written)
			assert.Equal(t, map[string]uint32{"1600000000.M1P1.host": 3, "1700000001.M1P1.host": 7}, written.UIDMappings)
		})
	}
}
