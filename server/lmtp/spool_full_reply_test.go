package lmtp

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"testing"

	"github.com/emersion/go-smtp"
)

// A delivery into a shared mailbox another account owns stages the body again for the
// owner (UploadWorker.LinkStagedOrStore). When the spool disk is full or read-only there,
// the reply must be the one the recipient's own copy gets for the same condition, 452
// 4.3.1, not a 451 4.3.0 server error (#1906).
func TestSaveFailedReplySpoolFullIs452(t *testing.T) {
	for _, tc := range []struct {
		errno        syscall.Errno
		code         int
		enhancedCode smtp.EnhancedCode
	}{
		{syscall.ENOSPC, 452, smtp.EnhancedCode{4, 3, 1}},
		{syscall.EROFS, 452, smtp.EnhancedCode{4, 3, 1}},
		{syscall.EACCES, 451, smtp.EnhancedCode{4, 3, 0}},
	} {
		t.Run(tc.errno.Error(), func(t *testing.T) {
			// Wrapped as saveMessageToMailbox wraps what LinkStagedOrStore returns from
			// stageFrom.
			tmp := "/private/spool/2/0123abcd.0000000000000001.tmp"
			err := fmt.Errorf("failed to stage message body for the owner of mailbox '%s': %w", "Shared/Team",
				fmt.Errorf("failed to create file %s: %w", tmp, &fs.PathError{Op: "open", Path: tmp, Err: tc.errno}))

			reply := (&LMTPSession{}).saveFailedReply("Shared/Team", err)
			var smtpErr *smtp.SMTPError
			if !errors.As(reply, &smtpErr) {
				t.Fatalf("reply %v is not an *smtp.SMTPError", reply)
			}
			if smtpErr.Code != tc.code || smtpErr.EnhancedCode != tc.enhancedCode {
				t.Fatalf("reply = %d %v %q, want %d %v", smtpErr.Code, smtpErr.EnhancedCode, smtpErr.Message, tc.code, tc.enhancedCode)
			}
			if strings.Contains(smtpErr.Message, "/private/spool") || strings.Contains(smtpErr.Message, "Shared/Team") {
				t.Fatalf("reply exposes the spool path or mailbox: %q", smtpErr.Message)
			}
		})
	}
}
