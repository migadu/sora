package helpers

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
)

// ValidateMIMEStructure checks headers and multipart boundaries before attachment
// classification. ExtractBodyStructure tolerates malformed MIME by synthesizing
// children or returning a partial tree; a serializable tree alone therefore
// cannot prove that a message has no attachments.
//
// The walk uses raw part readers: bodies need no charset/transfer decoding for
// classification, and embedded messages are attachments in their own right. The
// explicit stack avoids recursive calls for deeply nested multiparts.
func ValidateMIMEStructure(data []byte) error {
	reader := bufio.NewReader(bytes.NewReader(data))
	header, err := textproto.ReadHeader(reader)
	if err != nil {
		return err
	}
	var body io.Reader = reader
	var parents []*textproto.MultipartReader
	for {
		mimeHeader := message.Header{Header: header}
		mediaType, params, err := mimeHeader.ContentType()
		if err != nil {
			return err
		}
		if primary, subtype, ok := strings.Cut(mediaType, "/"); !ok || primary == "" || subtype == "" {
			return fmt.Errorf("invalid MIME media type %q", mediaType)
		}
		if mimeHeader.Get("Content-Disposition") != "" {
			if _, _, err := mimeHeader.ContentDisposition(); err != nil {
				return err
			}
		}
		if strings.HasPrefix(mediaType, "multipart/") {
			if params["boundary"] == "" {
				return fmt.Errorf("multipart has no boundary")
			}
			mr := textproto.NewMultipartReader(body, params["boundary"])
			part, err := mr.NextPart()
			if err != nil {
				// Even a clean EOF here means there was no real child. The
				// body structure extractor would insert a synthetic one.
				return fmt.Errorf("multipart has no readable first part: %w", err)
			}
			parents = append(parents, mr)
			header, body = part.Header, part
			continue
		}
		if _, err := io.Copy(io.Discard, body); err != nil {
			return err
		}
		for {
			if len(parents) == 0 {
				return nil
			}
			part, err := parents[len(parents)-1].NextPart()
			if err == io.EOF {
				parents = parents[:len(parents)-1]
				continue
			}
			if err != nil {
				return err
			}
			header, body = part.Header, part
			break
		}
	}
}
