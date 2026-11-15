package imap

import (
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
)

func TestStagingErrorCauseKeepsResponseClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code imap.ResponseCode
	}{
		{syscall.ENOSPC, imap.ResponseCodeUnavailable},
		{syscall.EROFS, imap.ResponseCodeUnavailable},
		{syscall.EACCES, imap.ResponseCodeServerBug},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			err := fmt.Errorf("staging /private/spool/account/hash: %w", &fs.PathError{
				Op: "write", Path: "/private/spool/account/hash", Err: tc.err,
			})
			response := (&IMAPSession{}).internalError("failed to save message to disk: %v", helpers.FileErrorCause(err))
			if response.Type != imap.StatusResponseTypeNo || response.Code != tc.code {
				t.Fatalf("response=%v, want NO [%s]", response, tc.code)
			}
			if strings.Contains(response.Text, "/private/spool") {
				t.Fatalf("response exposes staging path: %s", response.Text)
			}
		})
	}
}
