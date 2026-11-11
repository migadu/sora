package helpers

import (
	"bufio"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/emersion/go-message"
)

// PreviewMaxChars is the length of a generated preview, in characters. RFC 8970
// §4 asks for at most 200 and allows no more than 256.
const PreviewMaxChars = 200

const (
	// previewMaxInput bounds how much of the raw message is read, whatever its
	// size, so a preview costs the same from a cached file, a staging file or
	// a body already in memory, and always comes out the same (RFC 8970 §3:
	// the server SHOULD generate the same string for a message each time).
	previewMaxInput = 1 << 20
	// previewMaxText bounds how much of a text/plain part is read.
	previewMaxText = 64 << 10
	// previewMaxHTML bounds how much of a text/html part is read. It is larger
	// because newsletters carry tens of kilobytes of <head> and <style> before
	// the first word of text.
	previewMaxHTML = 256 << 10
	// Each MIME nesting level adds parser buffers and wraps the parent's reader.
	// Skip deeper subtrees while still looking for a shallower inline sibling.
	previewMaxMIMEDepth = 32
)

// MessagePreview returns a short plain-text preview of a raw RFC 5322 message
// for FETCH PREVIEW (RFC 8970): the start of its first inline text/plain part
// that has any text, else of its first text/html part converted to text.
// Attachments are never used. Quoted lines and the signature are left out,
// whitespace is collapsed, and the text is cut at a word boundary to
// PreviewMaxChars characters.
//
// It returns "" when the message has no text to show, including for encrypted
// messages: multipart/encrypted and S/MIME bodies have no text part, and an
// inline PGP message is recognised by its armor.
//
// This is deliberately separate from ExtractPlaintextBody, whose output is the
// stored full-text search text and must not change with preview tweaks.
func MessagePreview(r io.Reader) (preview string) {
	defer func() {
		if recover() != nil {
			preview = ""
		}
	}()

	entity, err := message.Read(bufio.NewReader(io.LimitReader(r, previewMaxInput)))
	if err != nil && !message.IsUnknownCharset(err) {
		return ""
	}
	// Inspect each entity before descending: mail.Reader flattens multiparts
	// and loses an attachment container's disposition on its inline leaves.
	var readers []message.MultipartReader
	defer func() {
		for i := len(readers) - 1; i >= 0; i-- {
			readers[i].Close()
		}
	}()

	html, haveHTML := "", false
	part := entity
	for {
		if part == nil {
			if len(readers) == 0 {
				break
			}
			mr := readers[len(readers)-1]
			part, err = mr.NextPart()
			if err == io.EOF {
				mr.Close()
				readers = readers[:len(readers)-1]
				part = nil
				continue
			}
			if err != nil && !message.IsUnknownCharset(err) {
				break // malformed part: retain any HTML already collected
			}
		}
		current := part
		part = nil
		disposition, _, _ := current.Header.ContentDisposition()
		if disposition == "attachment" {
			continue
		}
		mediaType, _, err := current.Header.ContentType()
		if err != nil {
			continue
		}
		if mediaType == "multipart/encrypted" {
			continue
		}
		if strings.HasPrefix(mediaType, "multipart/") {
			if len(readers) < previewMaxMIMEDepth {
				if mr := current.MultipartReader(); mr != nil {
					readers = append(readers, mr)
				}
			}
			// NextPart discards a skipped subtree as raw bytes, so it neither
			// allocates descendant parsers nor visits attachment contents.
			continue
		}
		switch mediaType {
		case "text/plain":
			b, _ := io.ReadAll(io.LimitReader(current.Body, previewMaxText))
			text := string(b)
			if isPGPMessage(text) {
				return ""
			}
			if p := previewFromText(text); p != "" {
				return p
			}
		case "text/html":
			if !haveHTML {
				b, _ := io.ReadAll(io.LimitReader(current.Body, previewMaxHTML))
				html, haveHTML = string(b), true
			}
		}
	}
	if haveHTML {
		return previewFromText(previewHTMLText(html))
	}
	return ""
}

func isPGPMessage(text string) bool {
	return strings.HasPrefix(strings.TrimSpace(text), "-----BEGIN PGP MESSAGE-----")
}

// previewFromText turns the text of a body part into a preview.
func previewFromText(text string) string {
	text = stripPGPClearsign(text)

	var own, quoted []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "-- " || line == "--" {
			break // signature delimiter (RFC 3676 §4.3)
		}
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), ">") {
			quoted = append(quoted, strings.TrimLeft(line, " \t>"))
			continue
		}
		own = append(own, line)
	}
	preview := collapsePreviewText(strings.Join(own, " "))
	if preview == "" {
		// A message that is nothing but a quote is still better shown than not.
		preview = collapsePreviewText(strings.Join(quoted, " "))
	}
	return truncatePreview(preview, PreviewMaxChars)
}

// stripPGPClearsign removes the armor of a clearsigned message (RFC 4880 §7),
// leaving the signed text.
func stripPGPClearsign(text string) string {
	const begin = "-----BEGIN PGP SIGNED MESSAGE-----"
	i := strings.Index(text, begin)
	if i < 0 {
		return text
	}
	rest := text[i+len(begin):]
	// Armor headers ("Hash: SHA256") run up to the first blank line.
	lines := strings.SplitAfter(rest, "\n")
	j := 0
	if len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		j = 1
	}
	for j < len(lines) && strings.TrimSpace(lines[j]) != "" {
		j++
	}
	body := strings.Join(lines[j:], "")
	if k := strings.Index(body, "-----BEGIN PGP SIGNATURE-----"); k >= 0 {
		body = body[:k]
	}
	return text[:i] + body
}

// collapsePreviewText collapses whitespace and drops what has no place in a
// one-line preview: control characters and invisible format characters,
// including the bidirectional overrides that could reorder the list row it is
// shown in. Zero-width joiners stay, since emoji sequences and some scripts
// need them.
func collapsePreviewText(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '‌' || r == '‍':
			return r
		case unicode.IsControl(r):
			return ' '
		case unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// truncatePreview cuts s to at most max characters, at the last space if there
// is one in the final quarter, so a word is not split when it can be avoided.
func truncatePreview(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)[:max]
	for i := len(runes) - 1; i >= max*3/4; i-- {
		if runes[i] == ' ' {
			return string(runes[:i])
		}
	}
	return string(runes)
}
