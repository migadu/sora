package helpers

import "fmt"

// NewS3Key constructs an S3 key for a message.
func NewS3Key(domain, localPart, hash string) string {
	return fmt.Sprintf("%s/%s/%s", domain, localPart, hash)
}
