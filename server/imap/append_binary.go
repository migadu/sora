package imap

import (
	"errors"
	"fmt"
	"math"

	"github.com/migadu/sora/helpers"
)

var errAppendBinaryTooLarge = errors.New("encoded binary APPEND exceeds maximum stored message size")

// normalizeBinaryAppend reserves the encoded message before the helper allocates
// it. The original literal remains charged until Append finishes as well.
func (s *IMAPSession) normalizeBinaryAppend(raw []byte) ([]byte, func(), error) {
	var reserved int64
	release := func() {
		if reserved > 0 {
			s.memTracker.Free(reserved)
			reserved = 0
		}
	}
	data, err := helpers.NormalizeBinaryAppend(raw, func(size int64) error {
		// messages.size is a PostgreSQL INTEGER, independently of the upload
		// limit already checked against the original literal by go-imap.
		if size > math.MaxInt32 {
			return errAppendBinaryTooLarge
		}
		if s.memTracker == nil {
			return nil
		}
		if !s.memoryAvailable(size) {
			return fmt.Errorf("%w: binary APPEND needs %d encoded bytes", errAppendLiteralTooLarge, size)
		}
		if err := s.memTracker.Allocate(size); err != nil {
			return fmt.Errorf("%w: %v", errAppendLiteralTooLarge, err)
		}
		reserved += size
		return nil
	})
	return data, release, err
}
