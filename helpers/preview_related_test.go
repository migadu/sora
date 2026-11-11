package helpers

import (
	"fmt"
	"strings"
	"testing"
)

func previewRelatedMultipart(boundary, mediaType, start string, parts ...string) string {
	subtype := fmt.Sprintf("related; type=%q", mediaType)
	if start != "" {
		subtype += fmt.Sprintf("; start=%q", start)
	}
	return previewMIMEMultipart(subtype, boundary, parts...)
}

func TestMessagePreviewRelatedRoot(t *testing.T) {
	plain := "Content-Type: text/plain\r\n\r\nPlain root"
	html := "Content-Type: text/html\r\n\r\n<p>HTML root</p>"
	auxiliary := "Content-Type: text/plain\r\n\r\nAuxiliary text"
	identified := func(id, part string) string {
		return "Content-ID: " + id + "\r\n" + part
	}
	root := identified("<root@example.com>", html)
	alternative := previewMIMEMultipart("alternative", "alternative", html, plain)
	innerRelated := previewRelatedMultipart("inner", "text/html", "<inner@example.com>", auxiliary,
		identified("<inner@example.com>", html), auxiliary)
	digest := previewMIMEMultipart("digest", "digest",
		"\r\nFrom: sender@example.com\r\nSubject: Encapsulated message\r\n\r\nDigest message text", plain)
	for _, tc := range []struct{ name, raw, want string }{
		{
			name: "named root follows linked HTML archive",
			raw: "MIME-Version: 1.0\r\n" + previewRelatedMultipart("related", "text/html", "<root@example.com>",
				identified("<archive@example.com>", "Content-Type: text/html; charset=utf-8\r\n\r\n<p>Archived message: The meeting is confirmed.</p>"),
				identified("<root@example.com>", "Content-Type: text/html; charset=utf-8\r\n\r\n<p>The meeting is cancelled.</p><a href=\"cid:archive@example.com\">Previous message</a>")),
			want: "The meeting is cancelled. Previous message",
		},
		{"default root is first child despite later plain auxiliary", previewRelatedMultipart("related", "text/html", "", html, auxiliary), "HTML root"},
		{"named root does not use later plain auxiliary", previewRelatedMultipart("related", "text/html", "<root@example.com>", root, auxiliary), "HTML root"},
		{"named root does not use earlier plain auxiliary", previewRelatedMultipart("related", "text/html", "<root@example.com>", auxiliary, root), "HTML root"},
		{"unsupported default root does not use auxiliary", previewRelatedMultipart("related", "application/octet-stream", "", "Content-Type: application/octet-stream\r\n\r\nBinary root", auxiliary), ""},
		{"missing named root does not use auxiliary", previewRelatedMultipart("related", "text/html", "<missing@example.com>", auxiliary, root), ""},
		{"empty start does not select a child without an ID", strings.Replace(previewRelatedMultipart("related", "text/html", "", auxiliary), "; boundary=", `; start=""; boundary=`, 1), ""},
		{"ID matching preserves case", previewRelatedMultipart("related", "text/html", "<Root@example.com>", identified("<root@example.com>", auxiliary), identified("<Root@example.com>", html)), "HTML root"},
		{"ID surrounding whitespace", previewRelatedMultipart("related", "text/html", " <root@example.com> ", identified(" \t<root@example.com> \t", html), auxiliary), "HTML root"},
		{"only first matching ID selects a root", previewRelatedMultipart("related", "text/html", "<root@example.com>", root, identified("<root@example.com>", auxiliary)), "HTML root"},
		{"root alternative retains plain preference", previewRelatedMultipart("related", "multipart/alternative", "<root@example.com>", auxiliary, identified("<root@example.com>", alternative), auxiliary), "Plain root"},
		{"auxiliary multipart is not traversed", previewRelatedMultipart("related", "text/html", "<root@example.com>", alternative, root), "HTML root"},
		{"nested related keeps its own selected root", previewRelatedMultipart("related", "multipart/related", "<root@example.com>", identified("<root@example.com>", innerRelated), auxiliary), "HTML root"},
		{"nested related does not hide an alternative sibling", previewRelatedMultipart("related", "multipart/alternative", "<root@example.com>", identified("<root@example.com>", previewMIMEMultipart("alternative", "alternative", innerRelated, plain)), auxiliary), "Plain root"},
		{"root digest retains direct child defaults", previewRelatedMultipart("related", "multipart/digest", "<root@example.com>", identified("<root@example.com>", digest), auxiliary), "Plain root"},
		{"related resets an enclosing digest default", previewMIMEMultipart("digest", "digest", previewRelatedMultipart("related", "text/plain", "", "\r\nDefault plain root", auxiliary)), "Default plain root"},
		{"missing related root preserves an enclosing HTML fallback", previewMIMEMultipart("mixed", "mixed", html, previewRelatedMultipart("related", "text/html", "<missing@example.com>", auxiliary)), "HTML root"},
		{"selected root disposition is ignored", previewRelatedMultipart("related", "text/html", "<root@example.com>", identified("<root@example.com>", "Content-Disposition: attachment\r\n"+html), auxiliary), "HTML root"},
		{"selected root unknown disposition is ignored", previewRelatedMultipart("related", "text/html", "<root@example.com>", identified("<root@example.com>", "Content-Disposition: x-private\r\n"+html), auxiliary), "HTML root"},
		{"root disposition exception does not reach grandchildren", previewRelatedMultipart("related", "multipart/alternative", "<root@example.com>", identified("<root@example.com>", "Content-Disposition: attachment\r\n"+previewMIMEMultipart("alternative", "alternative", "Content-Disposition: attachment\r\n"+auxiliary, html)), auxiliary), "HTML root"},
		{"outer attachment container remains excluded", previewMIMEMultipart("mixed", "mixed", "Content-Disposition: attachment\r\n"+previewRelatedMultipart("related", "text/html", "<root@example.com>", root), plain), "Plain root"},
		{"encrypted selected root does not use auxiliary", previewRelatedMultipart("related", "multipart/encrypted", "<root@example.com>", identified("<root@example.com>", previewMIMEMultipart("encrypted", "encrypted", auxiliary)), auxiliary), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MessagePreview(strings.NewReader(tc.raw)); got != tc.want {
				t.Errorf("MessagePreview() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMessagePreviewRelatedRootBudgets(t *testing.T) {
	t.Run("auxiliary children count toward part budget", func(t *testing.T) {
		for _, beforeRoot := range []int{previewMaxMIMEParts - 2, previewMaxMIMEParts - 1} {
			parts := make([]string, beforeRoot)
			for i := range parts {
				parts[i] = "Content-Type: text/plain\r\n\r\nAuxiliary text"
			}
			parts = append(parts, "Content-ID: <root@example.com>\r\nContent-Type: text/html\r\n\r\n<p>HTML root</p>")
			raw := previewRelatedMultipart("related", "text/html", "<root@example.com>", parts...)
			want := ""
			if beforeRoot == previewMaxMIMEParts-2 {
				want = "HTML root"
			}
			if got := MessagePreview(strings.NewReader(raw)); got != want {
				t.Errorf("%d auxiliaries: MessagePreview() = %q, want %q", beforeRoot, got, want)
			}
		}
	})
	t.Run("deep selected root still permits shallow outer sibling", func(t *testing.T) {
		root := "Content-Type: text/plain\r\n\r\nDeep root text"
		for depth := 0; depth < previewMaxMIMEDepth; depth++ {
			root = previewMIMEMultipart("mixed", fmt.Sprintf("deep%d", depth), root)
		}
		related := previewRelatedMultipart("related", "multipart/mixed", "<root@example.com>", "Content-ID: <root@example.com>\r\n"+root,
			"Content-Type: text/plain\r\n\r\nAuxiliary text")
		raw := previewMIMEMultipart("mixed", "outer", related, "Content-Type: text/plain\r\n\r\nShallow text")
		if got := MessagePreview(strings.NewReader(raw)); got != "Shallow text" {
			t.Errorf("MessagePreview() = %q, want Shallow text", got)
		}
	})
	t.Run("auxiliary bytes count toward raw input budget", func(t *testing.T) {
		raw := previewRelatedMultipart("related", "text/plain", "<root@example.com>",
			"Content-Type: text/plain\r\n\r\n"+strings.Repeat("x", previewMaxInput),
			"Content-ID: <root@example.com>\r\nContent-Type: text/plain\r\n\r\nRoot beyond input limit")
		r := &countingReader{r: strings.NewReader(raw)}
		if got := MessagePreview(r); got != "" {
			t.Errorf("MessagePreview() = %q, want no root beyond input limit", got)
		}
		if r.n > previewMaxInput {
			t.Errorf("read %d raw bytes, want at most %d", r.n, previewMaxInput)
		}
	})
}
