package helpers

import (
	"bytes"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// previewHTMLText extracts visible text without building a DOM. The tokenizer
// consumes each token once, including malformed markup, and both its input and
// the resulting text are bounded independently of the message's size.
func previewHTMLText(source string) string {
	if len(source) >= previewMaxHTML {
		source = source[:previewMaxHTML]
		// MessagePreview may already have cut the part at this byte limit.
		// Drop a final incomplete rune instead of manufacturing replacement
		// characters for bytes that belong to the unread part of the message.
		start := len(source) - 1
		for start > 0 && len(source)-start < utf8.UTFMax && !utf8.RuneStart(source[start]) {
			start--
		}
		if !utf8.FullRuneInString(source[start:]) {
			source = source[:start]
		}
	}
	z := html.NewTokenizer(strings.NewReader(source))
	// SetMaxBuf rejects a token when its size reaches the limit. Allow the
	// entire bounded input to form one text token before reaching EOF.
	z.SetMaxBuf(previewMaxHTML + 1)

	var out previewHTMLWriter
	var hidden string
	hiddenDepth, quoteDepth, preDepth := 0, 0, 0
	inHead := false
	for !out.full {
		token := z.Next()
		switch token {
		case html.ErrorToken:
			return string(out.text)
		case html.TextToken:
			if hidden == "" {
				text := z.Text()
				if inHead {
					if len(bytes.Trim(text, " \t\r\n\f")) == 0 {
						continue
					}
					inHead = false // non-whitespace text implicitly starts the body
				}
				out.writeText(text, quoteDepth > 0, preDepth > 0)
			}
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)
			closing := token == html.EndTagToken
			if hidden != "" {
				if tag == hidden {
					if closing {
						hiddenDepth--
					} else {
						hiddenDepth++
					}
					if hiddenDepth == 0 {
						hidden = ""
						out.space()
					}
				}
				continue
			}
			if tag == "head" {
				inHead = !closing
				continue
			}
			if inHead {
				if closing {
					if tag != "body" && tag != "html" && tag != "br" {
						continue
					}
					inHead = false
				} else if !previewHTMLHeadTag(tag) {
					// A body element implicitly closes head, even when both
					// </head> and <body> are omitted. Hidden head children are
					// tracked separately so their markup cannot start the body.
					inHead = false
				}
			}
			if !closing {
				switch tag {
				case "script", "style", "title", "template":
					out.space()
					// These are non-void HTML elements: a trailing slash on
					// their start tag does not make their content visible.
					hidden, hiddenDepth = tag, 1
					continue
				case "noscript", "noframes":
					if inHead {
						hidden, hiddenDepth = tag, 1
						continue
					}
				}
			}
			if inHead {
				continue
			}
			if tag == "pre" {
				if closing {
					if preDepth > 0 {
						preDepth--
					}
				} else {
					preDepth++
				}
			}
			if tag == "blockquote" {
				out.lineBreak()
				if closing {
					if quoteDepth > 0 {
						quoteDepth--
					}
				} else if token != html.SelfClosingTagToken {
					quoteDepth++
				}
			} else if previewHTMLBlockTag(tag) {
				out.lineBreak()
			}
		}
	}
	return string(out.text)
}

func previewHTMLHeadTag(tag string) bool {
	switch tag {
	case "html", "base", "basefont", "bgsound", "link", "meta", "title", "noscript", "noframes", "script", "style", "template":
		return true
	}
	return false
}

func previewHTMLBlockTag(tag string) bool {
	switch tag {
	case "address", "article", "aside", "body", "br", "caption", "dd", "div", "dl", "dt",
		"fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6",
		"header", "hr", "li", "main", "nav", "ol", "p", "pre", "section", "table", "td", "th", "tr", "ul":
		return true
	}
	return false
}

type previewHTMLWriter struct {
	text []byte
	full bool
}

func (w *previewHTMLWriter) writeRune(r rune) {
	if len(w.text)+utf8.RuneLen(r) > previewMaxHTML {
		w.full = true
		return
	}
	w.text = utf8.AppendRune(w.text, r)
	w.full = len(w.text) == previewMaxHTML
}

func (w *previewHTMLWriter) space() {
	if n := len(w.text); n > 0 && w.text[n-1] != ' ' && w.text[n-1] != '\n' {
		w.writeRune(' ')
	}
}

func (w *previewHTMLWriter) lineBreak() {
	if n := len(w.text); n > 0 && w.text[n-1] == ' ' {
		w.text = w.text[:n-1]
	}
	if n := len(w.text); n > 0 && w.text[n-1] != '\n' {
		w.writeRune('\n')
	}
}

func (w *previewHTMLWriter) writeText(text []byte, quoted, preformatted bool) {
	for len(text) > 0 && !w.full {
		r, size := utf8.DecodeRune(text)
		text = text[size:]
		if preformatted && (r == '\r' || r == '\n') {
			// Keep line boundaries until previewFromText has removed quoted
			// lines and signatures. HTML entities may decode to CR as well as LF.
			w.lineBreak()
			continue
		}
		if unicode.IsSpace(r) {
			w.space()
			continue
		}
		if quoted && (len(w.text) == 0 || w.text[len(w.text)-1] == '\n') {
			w.writeRune('>')
			w.writeRune(' ')
		}
		w.writeRune(r)
	}
}
