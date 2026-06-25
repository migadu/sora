package helpers

import (
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
