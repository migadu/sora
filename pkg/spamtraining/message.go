package spamtraining

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
)

// maxMIMEDepth bounds how many multipart levels StripAttachments descends.
// Each level holds its own parser buffer; deeper subtrees are dropped.
const maxMIMEDepth = 32

const noTextPlaceholder = "[No text content - attachments stripped for spam training]\n"

// StripAttachments removes all attachments from a MIME message body,
// keeping only text/plain and text/html parts for spam training.
//
// The text parts are found at any depth and kept byte for byte, headers and
// encoded body alike, so every header still describes the bytes that follow
// it. The multiparts that hold them keep their header and boundary; only the
// other parts and the preamble and epilogue are left out. A single-part
// message is returned as is.
func StripAttachments(messageBody []byte) ([]byte, error) {
	br := bufio.NewReader(bytes.NewReader(messageBody))
	header, err := textproto.ReadHeader(br)
	if err != nil {
		return nil, fmt.Errorf("failed to parse message: %w", err)
	}
	if mediaType, _ := partType(header, false); !strings.HasPrefix(mediaType, "multipart/") {
		return messageBody, nil
	}

	var buf bytes.Buffer
	kept, err := writeTextParts(&buf, header, br, false, 0)
	if err != nil {
		return nil, err
	}
	if kept {
		buf.WriteString("\r\n")
		return buf.Bytes(), nil
	}

	// No text anywhere: the message header with a placeholder body.
	buf.Reset()
	header.Del("Content-Transfer-Encoding")
	header.Set("Content-Type", "text/plain; charset=utf-8")
	if err := textproto.WriteHeader(&buf, header); err != nil {
		return nil, fmt.Errorf("failed to write header: %w", err)
	}
	buf.WriteString(noTextPlaceholder)
	return buf.Bytes(), nil
}

// partType returns the media type and parameters of an entity. A missing
// Content-Type means text/plain, or message/rfc822 for a direct child of a
// multipart/digest (RFC 2046 section 5.1.1).
func partType(header textproto.Header, inDigest bool) (string, map[string]string) {
	if inDigest && !header.Has("Content-Type") {
		return "message/rfc822", nil
	}
	h := message.Header{Header: header}
	mediaType, params, _ := h.ContentType()
	return mediaType, params
}

// writeTextParts writes the entity to w if it is a text/plain or text/html
// part, or a multipart holding one at any depth, with every other part left
// out. It reports whether anything was written; when nothing was, w is left
// as it was. On an error w may hold part of the entity, which the caller
// truncates.
func writeTextParts(w *bytes.Buffer, header textproto.Header, body io.Reader, inDigest bool, depth int) (bool, error) {
	mediaType, params := partType(header, inDigest)
	switch {
	case mediaType == "text/plain" || mediaType == "text/html":
		if err := textproto.WriteHeader(w, header); err != nil {
			return false, fmt.Errorf("failed to write part header: %w", err)
		}
		if _, err := io.Copy(w, body); err != nil {
			return false, fmt.Errorf("failed to read part body: %w", err)
		}
		return true, nil
	case !strings.HasPrefix(mediaType, "multipart/") || depth >= maxMIMEDepth:
		return false, nil
	}

	// The original boundary is reused: it cannot occur inside the parts it
	// delimited (RFC 2046 section 5.1.1), and leaving parts out cannot make
	// it occur.
	start := w.Len()
	if err := textproto.WriteHeader(w, header); err != nil {
		return false, fmt.Errorf("failed to write multipart header: %w", err)
	}
	boundary := params["boundary"]
	mr := textproto.NewMultipartReader(body, boundary)
	kept := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("failed to read multipart: %w", err)
		}

		// The CRLF before a boundary delimiter belongs to the delimiter
		// (RFC 2046 section 5.1.1), so the part body read here excludes it.
		mark := w.Len()
		if kept {
			w.WriteString("\r\n")
		}
		w.WriteString("--" + boundary + "\r\n")
		// A part that does not parse, such as a nested multipart without a
		// boundary or without its close delimiter, is left out like any
		// part without text, as it was before the walk descended. If it is
		// this multipart's own stream that broke, the next NextPart says so.
		ok, err := writeTextParts(w, part.Header, part, mediaType == "multipart/digest", depth+1)
		if ok && err == nil {
			kept = true
		} else {
			w.Truncate(mark)
		}
	}
	if !kept {
		w.Truncate(start)
		return false, nil
	}
	// The line break ending the close delimiter is left to the caller: in a
	// nested multipart it is the one before the parent's next delimiter.
	w.WriteString("\r\n--" + boundary + "--")
	return true, nil
}
