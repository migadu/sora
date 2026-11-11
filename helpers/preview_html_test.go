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
