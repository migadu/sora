package server

import (
	"bufio"
	"errors"
	"io"
)

var (
	// ErrLineTooLong is returned when a line exceeds the maximum allowed length
	ErrLineTooLong = errors.New("line too long")
)

// ReadBoundedLine reads a line from the reader up to maxBytes.
// Returns ErrLineTooLong if the line (including \n) exceeds maxBytes.
// The returned line includes the trailing \n if present.
func ReadBoundedLine(reader *bufio.Reader, maxBytes int) (string, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		line = append(line, chunk...)

		// Check if we've exceeded the limit
		if len(line) > maxBytes {
			// Drain the rest of the line to avoid desync (only if not at EOF)
			if err == nil {
				// We found \n and already exceeded limit
				return "", ErrLineTooLong
			}
			if err == bufio.ErrBufferFull {
				// Keep draining until we find \n or EOF
				for {
					_, drainErr := reader.ReadSlice('\n')
					if drainErr == nil {
						// Found \n, done draining
						return "", ErrLineTooLong
					}
					if drainErr != bufio.ErrBufferFull {
						// EOF or other error - line too long regardless
						return "", ErrLineTooLong
					}
					// Continue draining
				}
			}
			// EOF or other error while over limit - line is too long
			return "", ErrLineTooLong
		}

		// Within limit - check if we're done
		if err == nil {
			// Found \n and within limit
			return string(line), nil
		}

		if err == bufio.ErrBufferFull {
			// Need to read more, continue
			continue
		}

		// EOF or other error
		if err == io.EOF {
			if len(line) > 0 {
				// Last line without \n - already checked limit above
				return string(line), nil
			}
			// EOF with no data
			return "", io.EOF
		}

		return "", err
	}
}
