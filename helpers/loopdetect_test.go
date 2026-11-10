package helpers

import (
	"fmt"
	"strings"
	"testing"
)

func TestDeliveredToLoop(t *testing.T) {
	get := HeaderGetter(map[string][]string{
		"Delivered-To": {"alice@example.com", " Bob@Example.com "},
		"Subject":      {"hi"},
	})
	cases := []struct {
		addr string
		want bool
	}{
		{"alice@example.com", true},
		{"ALICE@EXAMPLE.COM", true},  // case-insensitive
		{"bob@example.com", true},    // case-insensitive + trims surrounding space
		{"carol@example.com", false}, // not present
		{"", false},                  // empty never loops
	}
	for _, c := range cases {
		if got := DeliveredToLoop(get, c.addr); got != c.want {
			t.Errorf("DeliveredToLoop(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
	// No Delivered-To header at all.
	if DeliveredToLoop(HeaderGetter(map[string][]string{"Subject": {"x"}}), "alice@example.com") {
		t.Errorf("DeliveredToLoop with no Delivered-To header should be false")
	}
}

func TestRedirectHopCount(t *testing.T) {
	cases := []struct {
		hdr  map[string][]string
		want int
	}{
		{map[string][]string{}, 0},
		{map[string][]string{"X-Sora-Loop": {"1"}}, 1},
		{map[string][]string{"x-sora-loop": {"7"}}, 7},      // case-insensitive
		{map[string][]string{"X-Sora-Loop": {"2", "5"}}, 5}, // highest wins
		{map[string][]string{"X-Sora-Loop": {"oops"}}, 0},   // unparseable -> 0
	}
	for i, c := range cases {
		if got := RedirectHopCount(HeaderGetter(c.hdr)); got != c.want {
			t.Errorf("case %d: RedirectHopCount = %d, want %d", i, got, c.want)
		}
	}
}

func TestPrependHeaderLine(t *testing.T) {
	out := string(PrependHeaderLine([]byte("Subject: hi\r\n\r\nbody"), "Delivered-To", "alice@example.com"))
	if !strings.HasPrefix(out, "Delivered-To: alice@example.com\r\nSubject: hi\r\n") {
		t.Errorf("prepended header not at top: %q", out)
	}
	if !strings.HasSuffix(out, "\r\nbody") {
		t.Errorf("original body not preserved: %q", out)
	}
	// CR/LF in the value must be stripped so it cannot inject a new header line.
	inj := string(PrependHeaderLine([]byte("body"), "X-Sora-Loop", "1\r\nInjected: evil"))
	if strings.Contains(inj, "\nInjected:") {
		t.Errorf("CRLF not stripped from header value (header injected): %q", inj)
	}
}

func TestSetHeaderLine(t *testing.T) {
	const name = "X-Redirected-By"
	const replacement = "X-Redirected-By: alice@a.ch\r\n"
	for _, newline := range []string{"\r\n", "\n"} {
		t.Run(fmt.Sprintf("newline=%q", newline), func(t *testing.T) {
			// The old values may be duplicated, mixed-case, and folded. Leave
			// unrelated folded headers, signatures, and body bytes exactly intact.
			retained := strings.Join([]string{
				"Received: from mx.example.com", "\tby mail.example.com; now",
				"DKIM-Signature: v=1; b=abc", " def==", "Subject: hello", "",
				"X-Redirected-By: body content", "\tmore body", "body\x00\xff",
			}, newline)
			original := strings.Join([]string{
				"x-redirected-by: attacker@example.com", " folded old value",
				"Received: from mx.example.com", "\tby mail.example.com; now",
				"X-Redirected-By: old@example.com", "\tanother old value",
				"X-Redirected-By \t: older@example.com", " folded whitespace-name value",
				"DKIM-Signature: v=1; b=abc", " def==", "Subject: hello", "",
				"X-Redirected-By: body content", "\tmore body", "body\x00\xff",
			}, newline)
			input := []byte(original)
			got := SetHeaderLine(input, name, "alice@a.ch")
			if string(got) != replacement+retained {
				t.Errorf("SetHeaderLine changed unrelated bytes:\ngot  %q\nwant %q", got, replacement+retained)
			}
			if string(input) != original {
				t.Fatal("SetHeaderLine mutated the input")
			}
		})
	}

	for _, msg := range []string{"", "\r\nbody", "Subject: hello\r\n\r\nbody", "Subject: unterminated"} {
		if got := string(SetHeaderLine([]byte(msg), name, "alice@a.ch")); got != replacement+msg {
			t.Errorf("SetHeaderLine(%q) = %q, want %q", msg, got, replacement+msg)
		}
	}
	if got := string(SetHeaderLine([]byte("x-redirected-by: old@example.com"), name, "alice@a.ch")); got != replacement {
		t.Errorf("unterminated old header retained: %q", got)
	}
	if got := string(SetHeaderLine([]byte("X-Redirected-By: old\r\n\r\nbody"), "X-Redirected-\r\nBy", "alice@a.ch\r\nInjected: evil")); got != "X-Redirected-By: alice@a.chInjected: evil\r\n\r\nbody" {
		t.Errorf("header injection not sanitized or existing field retained: %q", got)
	}
}

func TestIsRedirectLoop(t *testing.T) {
	// Legitimately forwarded inbound mail: Delivered-To present, no X-Sora-Loop -> not a loop.
	upstream := HeaderGetter(map[string][]string{"Delivered-To": {"alice@example.com"}})
	if IsRedirectLoop(upstream, "alice@example.com") {
		t.Errorf("upstream Delivered-To without X-Sora-Loop must not be treated as a loop")
	}
	// Sora redirect loop: our X-Sora-Loop marker present AND Delivered-To matches.
	looped := HeaderGetter(map[string][]string{"Delivered-To": {"alice@example.com"}, "X-Sora-Loop": {"1"}})
	if !IsRedirectLoop(looped, "alice@example.com") {
		t.Errorf("X-Sora-Loop + matching Delivered-To must be a loop")
	}
	// X-Sora-Loop present but Delivered-To is for a different recipient -> not a loop.
	if IsRedirectLoop(looped, "bob@example.com") {
		t.Errorf("X-Sora-Loop without a matching Delivered-To must not be a loop")
	}
}

func TestBuildReceivedHeader(t *testing.T) {
	got := BuildReceivedHeader(ReceivedFrom("mx.example.com", "203.0.113.5"),
		"mail.sora.test", "LMTP", "user@sora.test", "abc123", "Tue, 01 Jan 2030 12:00:00 +0000")
	for _, want := range []string{
		"Received: from mx.example.com ([203.0.113.5])",
		"by mail.sora.test with LMTP id abc123",
		"for <user@sora.test>;",
		"Tue, 01 Jan 2030 12:00:00 +0000",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Received header missing %q in:\n%s", want, got)
		}
	}

	// A hostile HELO must not inject a new header line.
	inj := BuildReceivedHeader(ReceivedFrom("evil\r\nInjected: x", "1.2.3.4"), "h", "LMTP", "u@d", "id", "date")
	if strings.Contains(inj, "\nInjected:") {
		t.Errorf("CRLF not stripped from from-clause (header injected): %q", inj)
	}

	// Empty from/for/id clauses are omitted.
	got2 := BuildReceivedHeader("", "h", "HTTP", "", "", "date")
	if strings.Contains(got2, "from ") || strings.Contains(got2, "for <") || strings.Contains(got2, " id ") {
		t.Errorf("empty clauses should be omitted: %q", got2)
	}
}
