package server

import (
	"fmt"
	"io"
	"log"

	"github.com/emersion/go-message"
	"github.com/google/uuid"
)

// ParseMessage reads and parses the email message from an io.Reader
func ParseMessage(r io.Reader) (*message.Entity, error) {
	// Read the message from the reader
	m, err := message.Read(r)
	if message.IsUnknownCharset(err) {
		log.Println("Unknown encoding:", err)
	} else if err != nil {
		return nil, fmt.Errorf("failed to read message: %v", err)
	}

	return m, nil
}

// ExtractParts processes the message entity and extracts MIME parts or content
func ExtractParts(m *message.Entity) error {
	if mr := m.MultipartReader(); mr != nil {
		// It's a multipart message
		log.Println("This is a multipart message containing:")
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			} else if err != nil {
				return fmt.Errorf("failed to read next part: %v", err)
			}

			// Process each part (e.g., extract content or metadata)
			t, _, _ := p.Header.ContentType()
			log.Println("A part with type:", t)
			// Here you can process the part (e.g., store it in S3)
		}
	} else {
		// It's a non-multipart message
		t, _, _ := m.Header.ContentType()
		log.Println("This is a non-multipart message with type:", t)
		// Process the message body or headers
	}

	return nil
}

// Helper function to generate an S3 key for a user and message
func S3Key(user *SoraUser, s3id uuid.UUID) string {
	return fmt.Sprintf("%s/%s/%s", user.domain, user.localPart, s3id.String())
}
