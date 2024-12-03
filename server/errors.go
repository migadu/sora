package server

import (
	"fmt"

	"github.com/emersion/go-imap/v2"
)

// Helper function to create an internal server error
func newInternalServerError(format string, a ...interface{}) *imap.Error {
	return &imap.Error{
		Type: imap.StatusResponseTypeNo,
		Code: imap.ResponseCodeServerBug,
		Text: fmt.Sprintf(format, a...),
	}
}
