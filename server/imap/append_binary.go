package imap

import (
	"errors"
	"fmt"
	"math"

	"github.com/migadu/sora/helpers"
)

var errAppendBinaryTooLarge = errors.New("encoded binary APPEND exceeds maximum stored message size")

// appendOutputReservation returns the reserve callback for a helper that
// re-encodes an APPEND literal, and the release for what it reserved. The
// helper calls it with the encoded message's full size before allocating it,
// and all of it is charged: the original literal remains charged (and
// referenced) until Append finishes, so both buffers are resident at once. A
// refused reservation leaves nothing reserved.
func (s *IMAPSession) appendOutputReservation() (func(int64) error, func()) {
	var reserved int64
	release := func() {
		if reserved > 0 {
			s.memTracker.Free(reserved)
			reserved = 0
		}
	}
	reserve := func(size int64) error {
		// messages.size is a PostgreSQL INTEGER, independently of the upload
		// limit already checked against the original literal by go-imap.
		if size > math.MaxInt32 {
			return errAppendBinaryTooLarge
		}
		if s.memTracker == nil {
			return nil
		}
		if !s.memoryAvailable(size) {
			return fmt.Errorf("%w: APPEND needs %d encoded bytes", errAppendLiteralTooLarge, size)
		}
		if err := s.memTracker.Allocate(size); err != nil {
			return fmt.Errorf("%w: %v", errAppendLiteralTooLarge, err)
		}
		reserved += size
		return nil
	}
	return reserve, release
}

// normalizeBinaryAppend normalizes a literal8 (BINARY) APPEND, reserving the
// encoded message before the helper allocates it.
func (s *IMAPSession) normalizeBinaryAppend(raw []byte) ([]byte, func(), error) {
	reserve, release := s.appendOutputReservation()
	data, err := helpers.NormalizeBinaryAppend(raw, reserve)
	return data, release, err
}

// encodeNULAppend re-encodes the NUL-bearing parts of every other APPEND: an
// ordinary literal, or the literal8 of the UTF8 data extension (RFC 6855 §4),
// which go-imap does not mark Binary. The encoded message is reserved before
// the helper allocates it.
func (s *IMAPSession) encodeNULAppend(raw []byte) ([]byte, func(), error) {
	reserve, release := s.appendOutputReservation()
	data, _, err := helpers.EncodeNULParts(raw, reserve)
	return data, release, err
}
