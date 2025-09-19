package helpers

import (
	"bytes"
	"encoding/gob"

	"github.com/emersion/go-imap/v2"
)

func init() {
	// Register the types that implement the BodyStructure interface
	gob.Register(&imap.BodyStructureSinglePart{})
	gob.Register(&imap.BodyStructureMultiPart{})
	gob.Register(&imap.BodyStructureText{})
	gob.Register(&imap.BodyStructureMessageRFC822{})
}

// Serialize the BodyStructure to Gob
func SerializeBodyStructureGob(bs *imap.BodyStructure) ([]byte, error) {
	// Handle nil pointer by creating a default body structure
	if bs == nil {
		defaultBodyStructure := &imap.BodyStructureSinglePart{
			Type:    "text",
			Subtype: "plain",
			Size:    0,
		}
		var defaultBS imap.BodyStructure = defaultBodyStructure
		bs = &defaultBS
	}
	
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(bs); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Deserialize the Gob to BodyStructure
func DeserializeBodyStructureGob(data []byte) (*imap.BodyStructure, error) {
	var bs imap.BodyStructure
	dec := gob.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&bs); err != nil {
		return nil, err
	}
	return &bs, nil
}
