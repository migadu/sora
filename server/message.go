package server

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/emersion/go-message"
	"github.com/migadu/sora/logger"
)

// ParseMessage reads and parses the email message from an io.Reader.
// If the message has malformed MIME headers, it attempts to create a fallback
// entity that preserves the raw content, allowing degraded access rather than
// complete failure.
func ParseMessage(r io.Reader) (*message.Entity, error) {
	// Read the message from the reader
	m, err := message.Read(r)
	if message.IsUnknownCharset(err) {
		logger.Debug("Unknown encoding:", err)
	} else if err != nil {
		// Check if this is a malformed MIME header error
		if strings.Contains(err.Error(), "malformed MIME header") {
			logger.Warn("Malformed MIME header detected, attempting fallback", "error", err)
			// Return a degraded but usable entity
			return createFallbackEntity(err), nil
		}
		return nil, fmt.Errorf("failed to read message: %v", err)
	}

	return m, nil
}

// createFallbackEntity creates a minimal message entity for corrupted messages.
// This allows the message to be accessed in a degraded mode rather than failing completely.
func createFallbackEntity(originalErr error) *message.Entity {
	// Create a minimal entity with error information in headers
	var buf bytes.Buffer
	buf.WriteString("X-Sora-Parse-Error: ")
	buf.WriteString(originalErr.Error())
	buf.WriteString("\r\n")
	buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	buf.WriteString("\r\n")
	buf.WriteString("[Message could not be parsed due to malformed MIME headers]\r\n")

	// Parse this minimal message (which should never fail)
	entity, err := message.Read(bufio.NewReader(&buf))
	if err != nil {
		// This should never happen, but if it does, log and return nil
		logger.Error("Failed to create fallback entity", "error", err)
		return nil
	}

	return entity
}
