//go:build darwin || linux

package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/stretchr/testify/require"
)

// The scan's walk finds that an entry of the maildir is a folder and then opens it to
// list it. The maildir's owner can swap a folder and a FIFO with one rename (swapPaths)
// in between, and an open that meets the FIFO waits for a writer: the scan never
// returned (#1608).
func TestScanMaildirDoesNotWaitOnAFolderSwappedForAFIFO(t *testing.T) {
	const name = "1700000001.M1P1.host:2,S"
	maildirPath := newMaildirWith(t, map[string][]byte{name: cachedSizeMessage("One", 100)})
	var pairs [][2]string
	for k := 0; k < 20; k++ {
		folder := filepath.Join(maildirPath, fmt.Sprintf(".Folder%02d", k))
		fifo := filepath.Join(maildirPath, fmt.Sprintf(".Fifo%02d", k))
		require.NoError(t, os.Mkdir(folder, 0755))
		mkfifo(t, fifo)
		pairs = append(pairs, [2]string{folder, fifo})
	}
	if err := swapPaths(pairs[0][0], pairs[0][1]); err != nil {
		t.Skipf("this filesystem cannot swap a directory and a FIFO: %v", err)
	}
	importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
	// Every scan names each swapped folder it cannot list.
	defer logger.Swap(logger.Swap(slog.New(slog.NewTextHandler(io.Discard, nil))))

	stop := make(chan struct{})
	var swappers sync.WaitGroup
	for _, pair := range pairs {
		swappers.Add(1)
		go func() {
			defer swappers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = swapPaths(pair[0], pair[1])
			}
		}()
	}

	// The scans run until one fails (a folder that is no longer one when listed is a
	// scan error, as any folder that cannot be listed) or a second has passed.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
			if importer.scanMaildir() != nil {
				return
			}
		}
	}()
	var returned bool
	select {
	case <-done:
		returned = true
	case <-time.After(time.Second + fifoWait):
	}
	close(stop)
	swappers.Wait()
	// A scan that waits on a FIFO is released by opening every FIFO for writing.
	for !returned {
		for _, pair := range pairs {
			for _, path := range pair {
				if w, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					w.Close()
				}
			}
		}
		select {
		case <-done:
			returned = true
			t.Fatal("the scan waited on a folder that was swapped for a FIFO")
		case <-time.After(50 * time.Millisecond):
		}
	}
}
