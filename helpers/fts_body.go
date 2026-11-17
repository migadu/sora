package helpers

import "github.com/emersion/go-message"

// FTSPlaintextBody returns the text a message is stored with for full-text search
// (db.InsertMessageOptions.PlaintextBody): the text ExtractPlaintextBody found, or ""
// when the message has no text part. Every path that stores a message takes it from
// here, so a message is searchable the same way however it arrived.
//
// Extraction is best effort: a part it had to skip does not cost the message the text
// of the parts it could read. A non-nil error names the skipped parts for the caller
// to log; it never means the returned text is unusable.
func FTSPlaintextBody(msg *message.Entity) (string, error) {
	text, err := ExtractPlaintextBody(msg)
	if text == nil {
		return "", err
	}
	return *text, err
}
