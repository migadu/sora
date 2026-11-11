package delivery

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/server/sieveengine"
)

// queueVacationReply runs `reply` to a parent carrying `parentHeaders` through the
// real handler and returns the queued reply parsed with go-message's mail reader,
// together with the bytes the relay would send.
func queueVacationReply(t *testing.T, reply sieveengine.VacationReply, parentHeaders map[string]string) (*mail.Reader, []byte) {
	t.Helper()
	q := &captureRelayQueue{}
	h := &StandardVacationHandler{Hostname: "mail.example.com", RelayQueue: q}
	if err := h.HandleVacationResponse(context.Background(), 42, reply, vacAddr(t, "sender@example.net"), vacAddr(t, "owner@example.com"), makeMessage(parentHeaders)); err != nil {
		t.Fatalf("HandleVacationResponse: %v", err)
	}
	if len(q.calls) != 1 {
		t.Fatalf("queued %d replies, want 1", len(q.calls))
	}
	wire := q.calls[0].body
	mr, err := mail.CreateReader(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("parse queued reply: %v\n%s", err, wire)
	}
	return mr, wire
}

// compileVacation compiles `script` with the vacation extension and returns the reply
// it produces for a minimal personal message.
func compileVacation(t *testing.T, script string) sieveengine.VacationReply {
	t.Helper()
	e, err := sieveengine.NewSieveExecutorWithExtensions(script, []string{"vacation"})
	if err != nil {
		t.Fatalf("compile script: %v", err)
	}
	r, err := e.Evaluate(context.Background(), sieveengine.Context{EnvelopeFrom: "sender@example.net", EnvelopeTo: "owner@example.com", Header: map[string][]string{"To": {"owner@example.com"}}, Message: []byte("To: owner@example.com\r\n\r\nhello")})
	if err != nil {
		t.Fatalf("evaluate script: %v", err)
	}
	if r.Vacation == nil {
		t.Fatalf("script produced no vacation reply (action %s)", r.Action)
	}
	return *r.Vacation
}

// TestVacationReplyReferences checks the reply's In-Reply-To and References against
// RFC 5322 §3.6.4: References is the parent's References (if any) followed by the
// parent's Message-ID (if any); a parent without References but with a single-id
// In-Reply-To contributes that id instead; a parent with none of the three gets no
// References field at all.
func TestVacationReplyReferences(t *testing.T) {
	for _, tc := range []struct {
		name       string
		parent     map[string]string
		references string // exact field value; "" means the field must be absent
		inReplyTo  string // exact field value; "" means the field must be absent
	}{
		{
			name:       "parent References chain followed by its Message-ID",
			parent:     map[string]string{"Message-ID": "<c@example.com>", "References": "<a@example.com> <b@example.com>"},
			references: "<a@example.com> <b@example.com> <c@example.com>",
			inReplyTo:  "<c@example.com>",
		},
		{
			name:       "single In-Reply-To stands in for a missing References",
			parent:     map[string]string{"Message-ID": "<mid@example.com>", "In-Reply-To": "<x@example.com>"},
			references: "<x@example.com> <mid@example.com>",
			inReplyTo:  "<mid@example.com>",
		},
		{
			name:       "Message-ID only",
			parent:     map[string]string{"Message-ID": "<mid@example.com>"},
			references: "<mid@example.com>",
			inReplyTo:  "<mid@example.com>",
		},
		{
			name:   "no References, In-Reply-To or Message-ID",
			parent: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := evaluateVacation(t, &fakeVacationOracle{}, "sender@example.net")
			mr, wire := queueVacationReply(t, reply, tc.parent)
			for name, want := range map[string]string{"References": tc.references, "In-Reply-To": tc.inReplyTo} {
				got := mr.Header.Values(name)
				switch {
				case want == "" && len(got) != 0:
					t.Errorf("%s=%q, want no field; wire=\n%s", name, got, wire)
				case want != "" && (len(got) != 1 || got[0] != want):
					t.Errorf("%s=%q, want [%q]; wire=\n%s", name, got, want, wire)
				}
			}
		})
	}
}

// TestVacationReplyReferencesLongChainFolds sends a parent whose References chain is
// far too long for one line and checks the reply folds it (RFC 5322 §2.1.1) without
// losing or corrupting any msg-id.
func TestVacationReplyReferencesLongChainFolds(t *testing.T) {
	var ids []string
	for i := 1; i <= 20; i++ {
		ids = append(ids, fmt.Sprintf("thread-message-%02d@example.com", i))
	}
	parent := map[string]string{"Message-ID": "<mid@example.com>", "References": "<" + strings.Join(ids, "> <") + ">"}
	reply := evaluateVacation(t, &fakeVacationOracle{}, "sender@example.net")
	mr, wire := queueVacationReply(t, reply, parent)

	got, err := mr.Header.MsgIDList("References")
	if err != nil {
		t.Fatalf("References does not parse back: %v; wire=\n%s", err, wire)
	}
	want := append(ids, "mid@example.com")
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("References ids=%q, want %q; wire=\n%s", got, want, wire)
	}
	raw, err := mr.Header.Raw("References")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\r\n"), "\r\n")
	if len(lines) < 2 {
		t.Errorf("References not folded: %q", raw)
	}
	for _, line := range lines {
		if len(line) > 78 {
			t.Errorf("References line of %d octets exceeds 78: %q", len(line), line)
		}
	}
}

// TestVacationReplyPrecedenceBulk checks that both the plain and the :mime reply carry
// Precedence: bulk (RFC 3834 §3.1.8, as Pigeonhole sends), and that a :mime reason
// cannot replace it.
func TestVacationReplyPrecedenceBulk(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply sieveengine.VacationReply
	}{
		{"plain", evaluateVacation(t, &fakeVacationOracle{}, "sender@example.net")},
		{":mime", compileVacation(t, "require \"vacation\"; vacation :subject \"Away\" :mime text:\nPrecedence: list\nContent-Type: text/html; charset=utf-8\n\n<p>Away</p>\n.\n;")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (tc.name == ":mime") != tc.reply.IsMime {
				t.Fatalf("IsMime=%v for %s reply", tc.reply.IsMime, tc.name)
			}
			mr, wire := queueVacationReply(t, tc.reply, map[string]string{"Message-ID": "<mid@example.com>"})
			if got := mr.Header.Values("Precedence"); len(got) != 1 || got[0] != "bulk" {
				t.Errorf("Precedence=%q, want [\"bulk\"]; wire=\n%s", got, wire)
			}
		})
	}
}
