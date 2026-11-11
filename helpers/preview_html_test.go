package helpers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestPreviewHTMLText(t *testing.T) {
	for _, tc := range []struct {
		name, html, want string
	}{
		{"inline text and entities", `<p>Hello <strong>there</strong>, <a href="https://example.com">Alice &amp; Bob</a>&nbsp;!</p>`, "Hello there, Alice & Bob !"},
		{"hidden sections", `<html><head><title>Title</title><style>p { color: red }</style></head><body><p>Hello</p><script>if (a > b) alert("<p>hidden</p>")</script><style>.x{display:none}</style><title>Hidden title</title><template>Hidden <template>nested</template> text</template><p>there</p></body></html>`, "Hello there"},
		{"implicit head end", `<head><title>Title</title><body><p>Message text</p>`, "Message text"},
		{"comments and attributes", `<!-- secret --><p title="hidden > text">Visible <img src="data:image/png;base64,` + strings.Repeat("a", 1024) + `"> words</p>`, "Visible words"},
		{"paragraphs and table cells", `<div>First</div><p>Second<br>Third</p><table><tr><td>Fourth</td><td>Fifth</td></tr></table>`, "First Second Third Fourth Fifth"},
		{"quoted lines", `<p>Sounds good.</p><p>&gt; Shall we meet?</p>`, "Sounds good."},
		{"blockquote", `<p>Sounds good.</p><blockquote><p>Shall we meet?</p><blockquote>Older quote</blockquote></blockquote>`, "Sounds good."},
		{"only a blockquote", `<blockquote><p>Forwarded line</p></blockquote>`, "Forwarded line"},
		{"signature", `<p>Message.</p><br>-- <br>Alice<br>Example Corp`, "Message."},
		{"unterminated script", `<p>Message.</p><script>hidden`, "Message."},
		{"non-void self-closing tag", `<script/>hidden</script><style/>hidden</style><title/>hidden</title><p>Message.</p>`, "Message."},
		{"malformed literal angle brackets", `Start <> > end`, "Start <> > end"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := previewFromText(previewHTMLText(tc.html)); got != tc.want {
				t.Fatalf("HTML preview = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPreviewHTMLTextBounds(t *testing.T) {
	t.Run("input", func(t *testing.T) {
		input := strings.Repeat(" ", previewMaxHTML) + "outside the input limit"
		if got := previewHTMLText(input); got != "" {
			t.Fatalf("read text past the input limit: %q", got)
		}
	})
	t.Run("decoded output", func(t *testing.T) {
		// HTML replaces each NUL byte with the three-byte replacement rune.
		got := previewHTMLText(strings.Repeat("\x00", previewMaxHTML))
		if len(got) > previewMaxHTML || len(got) < previewMaxHTML-utf8.UTFMax {
			t.Fatalf("decoded output has %d bytes, want at most %d", len(got), previewMaxHTML)
		}
		if !utf8.ValidString(got) {
			t.Fatal("output bound split a UTF-8 character")
		}
	})
	t.Run("one maximum size text token", func(t *testing.T) {
		input := "<" + strings.Repeat(">", previewMaxHTML-1)
		if got := previewHTMLText(input); got != input {
			t.Fatalf("malformed text changed: got %d bytes, want %d", len(got), len(input))
		}
	})
}

func TestMessagePreviewHTMLPreformatted(t *testing.T) {
	for _, tc := range []struct {
		name, html, want string
	}{
		{
			name: "bottom-posted reply after a long quote",
			html: "<pre>&gt; Earlier proposal: " + strings.Repeat("Please read the old proposal carefully. ", 10) +
				"\n\nNew reply: Reject the old proposal; use the revised budget instead.</pre>",
			want: "New reply: Reject the old proposal; use the revised budget instead.",
		},
		{
			name: "quote and reply across inline markup",
			html: "<pre>&gt; Quoted <b>old mail</b>\n\nNew <i>reply</i> here.</pre>",
			want: "New reply here.",
		},
		{
			name: "signature delimiter",
			html: "<pre>Actual message.\n\n-- \nAlice\nPrivate signature</pre>",
			want: "Actual message.",
		},
		{
			name: "signature across token boundaries",
			html: "<pre>Actual message.<span>\r\n</span>-- <b>\r\n</b>Alice</pre>",
			want: "Actual message.",
		},
		{
			name: "CRLF normalization",
			html: "<PRE>&gt; Earlier proposal\r\n\r\nApproved budget.</PRE>",
			want: "Approved budget.",
		},
		{
			name: "encoded CRLF",
			html: "<pre>&gt; Earlier proposal&#13;&#10;New reply.</pre>",
			want: "New reply.",
		},
		{
			name: "preformatted blockquote does not swallow following reply",
			html: "<blockquote><pre>Earlier proposal\nOlder detail</pre></blockquote><pre>New reply.</pre>",
			want: "New reply.",
		},
		{
			name: "hidden text inside preformatted content",
			html: "<pre>&gt; Earlier proposal\n<script>Not message text</script>New reply.</pre>",
			want: "New reply.",
		},
		{
			name: "ordinary HTML whitespace remains collapsed",
			html: "<p>&gt; Earlier\nproposal</p><p>New\nreply.</p>",
			want: "New reply.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := "Content-Type: text/html; charset=utf-8\r\n\r\n" + tc.html
			if got := MessagePreview(strings.NewReader(msg)); got != tc.want {
				t.Errorf("MessagePreview() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPreviewHTMLImplicitHeadEnd(t *testing.T) {
	for _, tc := range []struct {
		name, html, want string
	}{
		{"paragraph", `<head><meta charset=utf-8><p>Hello</p>`, "Hello"},
		{"plain text", `<head><title>Subject</title>Hello`, "Hello"},
		{"table", `<head><style>p{}</style><table><tr><td>Hello</td></tr></table>`, "Hello"},
		{"head template remains hidden", `<head><template><p>Hidden template text</p></template><p>Hello</p>`, "Hello"},
		{"head script remains hidden", `<head><script>"<p>Hidden script text</p>"</script><p>Hello</p>`, "Hello"},
		{"nested non-void self-closing template", `<template><template/>Inner</template><p>Still hidden</p></template><p>Hello</p>`, "Hello"},
		{"unclosed outer template remains hidden", `<template><template/>Inner</template><p>Still hidden</p>`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := previewFromText(previewHTMLText(tc.html)); got != tc.want {
				t.Errorf("HTML preview = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMessagePreviewHTMLUTF8Cutoff(t *testing.T) {
	for _, char := range []string{"é", "€", "🙂"} {
		for retained := 1; retained <= len(char); retained++ {
			t.Run(fmt.Sprintf("%U/%d_bytes", []rune(char)[0], retained), func(t *testing.T) {
				const beforePadding = "<head><style>"
				const afterPadding = "</style></head><body>Hello "
				padding := previewMaxHTML - retained - len(beforePadding) - len(afterPadding)
				html := beforePadding + strings.Repeat(" ", padding) + afterPadding + char + "</body>"
				msg := "Content-Type: text/html; charset=utf-8\r\n\r\n" + html
				want := "Hello"
				if retained == len(char) {
					want += " " + char
				}
				if got := MessagePreview(strings.NewReader(msg)); got != want {
					t.Errorf("MessagePreview() = %q, want %q", got, want)
				}
			})
		}
	}
}

// The old converter repeatedly rescanned a growing tag for every '>' in this
// message, spending tens of seconds on 256 KiB. Run the full MIME path in a
// subprocess so a regression cannot occupy the test process indefinitely. The
// deadline is generous compared with the tokenizer's millisecond-scale work;
// correctness is also checked independently of elapsed time.
func TestMessagePreviewHTMLMalformedAngles(t *testing.T) {
	const childEnv = "SORA_PREVIEW_HTML_REGRESSION_CHILD"
	if os.Getenv(childEnv) == "1" {
		msg := "Content-Type: multipart/alternative; boundary=b\r\n\r\n" +
			"--b\r\nContent-Type: text/plain\r\n\r\n \r\n" +
			"--b\r\nContent-Type: text/html\r\n\r\n<" + strings.Repeat(">", previewMaxHTML) + "\r\n--b--\r\n"
		want := "<" + strings.Repeat(">", PreviewMaxChars-1)
		if got := MessagePreview(strings.NewReader(msg)); got != want {
			t.Fatalf("MessagePreview() = %q, want %q", got, want)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMessagePreviewHTMLMalformedAngles$", "-test.count=1")
	cmd.Env = append(os.Environ(), childEnv+"=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("bounded HTML preview did not complete: %v\n%s", ctx.Err(), out)
	}
	if err != nil {
		t.Fatalf("HTML preview subprocess failed: %v\n%s", err, out)
	}
}

func BenchmarkPreviewHTMLMalformedAngles(b *testing.B) {
	for _, size := range []int{16 << 10, 64 << 10, previewMaxHTML} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			input := "<" + strings.Repeat(">", size-1)
			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				previewHTMLText(input)
			}
		})
	}
}
