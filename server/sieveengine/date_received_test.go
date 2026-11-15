package sieveengine

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

// TestDateReceived is issue #1376: the date test read only a header value that
// is a date-time as a whole, so the issue's script kept every message and a
// Received: field's :count was 0. RFC 5260 §4: "Implementations MUST support
// extraction of RFC 2822 date-time information that either makes up the entire
// header field ... or appears at the end of a header field following a
// semicolon (e.g., as it does in a standard Received: header field)." The
// header is read as delivery reads it, folded fields included.
func TestDateReceived(t *testing.T) {
	const script = `require ["date", "fileinto", "relational", "comparator-i;ascii-numeric"];
if date :originalzone "received" "hour" "02" { fileinto "match"; }
if date :count "eq" :comparator "i;ascii-numeric" "received" "date" "1" { fileinto "count"; }
`
	// What ManageSieve PUTSCRIPT checks, with the default [sieve] enabled_extensions.
	if err := ValidateScript(script, nil); err != nil {
		t.Fatalf("ValidateScript: %v", err)
	}
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, tc := range []struct {
		received string
		want     []string
	}{
		{"from mx.example.org by mail.example.com; Wed, 17 Jul 1996 02:23:25 -0700", []string{"match", "count"}},
		{"from mx.example.org (mx.example.org [192.0.2.1])\r\n\tby mail.example.com (Postfix) with ESMTPS id 4ABC\r\n\tfor <user@example.com>; Wed, 17 Jul 1996 02:23:25 -0700 (PDT)", []string{"match", "count"}},
		{"from mx.example.org by mail.example.com; Wed, 17 Jul 1996 03:23:25 -0700", []string{"count"}},
		{"from mx.example.org by mail.example.com; id 4ABC", nil},
		{"from mx.example.org by mail.example.com; Wed, 17 Jul 1996 02:23:25 -0700 (route; note)", []string{"match", "count"}},
		{"from mx.example.org by mail.example.com; Wed, 17 Jul 1996 02:23:25 -0700 (outer (inner; note))", []string{"match", "count"}},
		{"from mx.example.org by mail.example.com; Wed, 17 Jul 1996 02:23:25 -0700 (route; Wed, 17 Jul 1996 03:23:25 +0000)", []string{"match", "count"}},

	} {
		raw := "Received: " + tc.received + "\r\nFrom: sender@example.com\r\nSubject: test\r\n\r\nbody\r\n"
		entity, err := message.Read(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("%q: read: %v", tc.received, err)
		}
		result, err := executor.Evaluate(context.Background(), Context{
			EnvelopeFrom: "sender@example.com",
			EnvelopeTo:   "user@example.com",
			Header:       entity.Header.Map(),
			Message:      []byte(raw),
		})
		if err != nil {
			t.Fatalf("%q: evaluate: %v", tc.received, err)
		}
		if !slices.Equal(result.Mailboxes, tc.want) {
			t.Errorf("Received: %q: mailboxes = %q, want %q", tc.received, result.Mailboxes, tc.want)
		}
	}
}
