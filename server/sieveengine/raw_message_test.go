package sieveengine

import (
	"context"
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

func TestMessageBody(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want *string // nil: no body
	}{
		{"CRLF", "Subject: a\r\nFrom: b\r\n\r\nbody\r\n", ptr("body\r\n")},
		{"bare LF", "Subject: a\nFrom: b\n\nbody\n", ptr("body\n")},
		{"mixed endings", "Subject: a\r\nFrom: b\n\r\nbody", ptr("body")},
		{"folded header", "Subject: a\r\n b\r\n\r\nbody", ptr("body")},
		{"blank line inside body is not the separator", "Subject: a\r\n\r\none\r\n\r\ntwo", ptr("one\r\n\r\ntwo")},
		{"empty body", "Subject: a\r\n\r\n", ptr("")},
		{"no header block", "\r\nbody", ptr("body")},
		{"headers only", "Subject: a\r\nFrom: b\r\n", nil},
		{"no line ending", "Subject: a", nil},
		{"empty", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := messageBody([]byte(tt.msg))
			switch {
			case tt.want == nil && got != nil:
				t.Fatalf("want no body, got %q", got)
			case tt.want != nil && got == nil:
				t.Fatalf("want body %q, got none", *tt.want)
			case tt.want != nil && string(got) != *tt.want:
				t.Fatalf("want body %q, got %q", *tt.want, got)
			}
		})
	}
}

func ptr(s string) *string { return &s }

// TestHeadersOnlyMessageMatchesNoBodyTest pins RFC 5173 §4: a message that is a
// header only, with no empty line after it, has no body set at all, and every body
// test is false, "including those that test for an empty string".
func TestHeadersOnlyMessageMatchesNoBodyTest(t *testing.T) {
	ctx := Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header:       map[string][]string{"Subject": {"x"}, "From": {"sender@example.com"}},
		Message:      []byte("Subject: x\r\nFrom: sender@example.com\r\n"),
	}
	for _, script := range []string{
		`require ["body", "fileinto"]; if body :contains "" { fileinto "Hit"; }`,
		`require ["body", "fileinto"]; if body :is "" { fileinto "Hit"; }`,
		`require ["body", "fileinto"]; if body :raw :matches "*" { fileinto "Hit"; }`,
	} {
		executor, err := NewSieveExecutorWithExtensions(script, DefaultSieveExtensions)
		if err != nil {
			t.Fatalf("compile %q: %v", script, err)
		}
		res, err := executor.Evaluate(context.Background(), ctx)
		if err != nil {
			t.Fatalf("evaluate %q: %v", script, err)
		}
		if res.Action != ActionKeep {
			t.Errorf("%q matched a headers-only message: got %s", script, res.Action)
		}
	}
}

// rawContext builds a Context exactly as delivery does: both the header map and the
// raw message come from one parse of the same bytes.
func rawContext(t *testing.T, raw string) Context {
	t.Helper()
	entity, err := message.Read(strings.NewReader(raw))
	if err != nil && !message.IsUnknownCharset(err) {
		t.Fatal(err)
	}
	return Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header:       HeaderMap(entity.Header),
		Message:      []byte(raw),
	}
}

// TestEvaluateContextParsedLikeDelivery covers the Header/Message coupling the body
// test relies on (the top-level Content-Type from the map, the parts from the bytes)
// with a header map derived from the message as LMTP and the Admin API derive it,
// for the shapes that only a real parse gets right: a folded Content-Type and a
// bare-LF multipart.
func TestEvaluateContextParsedLikeDelivery(t *testing.T) {
	folded := "From: sender@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed;\r\n\tboundary=\"b\"\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\ninvoice 4711\r\n--b--\r\n"
	bareLF := "From: sender@example.com\nSubject: s\nMIME-Version: 1.0\n" +
		"Content-Type: multipart/mixed; boundary=\"b\"\n\n" +
		"--b\nContent-Type: text/plain\n\ninvoice 4711\n--b--\n"
	script := `require ["body", "fileinto"]; if body :contains "invoice 4711" { fileinto "Hit"; }`
	executor, err := NewSieveExecutorWithExtensions(script, DefaultSieveExtensions)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{"folded Content-Type": folded, "bare LF": bareLF} {
		res, err := executor.Evaluate(context.Background(), rawContext(t, raw))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Action != ActionFileInto {
			t.Errorf("%s: body text of the part not matched (got %s)", name, res.Action)
		}
	}
}

// TestEvaluateSeesRawMessage checks that the body test walks the MIME structure of
// Context.Message and that the size test measures all of it.
func TestEvaluateSeesRawMessage(t *testing.T) {
	attachment := strings.Repeat("JSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUl\r\n", 2000)
	msg := "From: sender@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n" +
		"--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\ninvoice 4711\r\n" +
		"--b\r\nContent-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		attachment + "--b--\r\n"
	ctx := Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header: map[string][]string{
			"From":         {"sender@example.com"},
			"Subject":      {"s"},
			"Content-Type": {`multipart/mixed; boundary="b"`},
		},
		Message: []byte(msg),
	}

	for _, tt := range []struct {
		script string
		want   Action
	}{
		{`require ["body", "fileinto"]; if body :contains "invoice 4711" { fileinto "Hit"; }`, ActionFileInto},
		{`require ["body", "fileinto"]; if body :content "application/pdf" :contains "" { fileinto "Hit"; }`, ActionFileInto},
		{`require ["fileinto"]; if size :over 100K { fileinto "Hit"; }`, ActionFileInto},
		{`require ["fileinto"]; if size :over 1M { fileinto "Hit"; }`, ActionKeep},
	} {
		executor, err := NewSieveExecutorWithExtensions(tt.script, DefaultSieveExtensions)
		if err != nil {
			t.Fatalf("compile %q: %v", tt.script, err)
		}
		res, err := executor.Evaluate(context.Background(), ctx)
		if err != nil {
			t.Fatalf("evaluate %q: %v", tt.script, err)
		}
		if res.Action != tt.want {
			t.Errorf("%q on a %d-byte multipart message: got %s, want %s", tt.script, len(msg), res.Action, tt.want)
		}
	}
}

// TestEvaluateRejectsEmptyMessage: a Context without Message is a programming
// error and must not evaluate as "no body, size 0".
func TestEvaluateRejectsEmptyMessage(t *testing.T) {
	executor, err := NewSieveExecutorWithExtensions(`require ["fileinto"]; if size :under 1K { fileinto "Small"; }`, DefaultSieveExtensions)
	if err != nil {
		t.Fatal(err)
	}
	_, err = executor.Evaluate(context.Background(), Context{Header: map[string][]string{"Subject": {"x"}}})
	if err == nil {
		t.Fatal("evaluated a Context with no Message")
	}
}
