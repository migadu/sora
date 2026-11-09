package delivery

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/emersion/go-message"
	"github.com/migadu/sora/server/sieveengine"
)

// TestVacationMIME follows a compiled :mime script through the shared LMTP and
// Admin API reply handler and inspects what the relay actually receives.
func TestVacationMIME(t *testing.T) {
	for _, tc := range []struct {
		name, reason, mediaType, body string
		multipart                     bool
	}{
		{"base64 HTML", "Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nPHA+QXdheTwvcD4=\r\n", "text/html", "<p>Away</p>", false},
		{"quoted printable text", "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nCaf=C3=A9\r\n", "text/plain", "Café\r\n", false},
		{"multipart alternative", "Content-Type: multipart/alternative; boundary=away\r\n\r\n--away\r\nContent-Type: text/plain\r\n\r\nAway\r\n--away\r\nContent-Type: text/html\r\n\r\n<p>Away</p>\r\n--away--\r\n", "multipart/alternative", "", true},
		{"transport headers cannot override generated headers", "From: spoof@example.net\r\nTo: victim@example.net\r\nSubject: Spoof\r\nMessage-ID: <spoof@example.net>\r\nAuto-Submitted: no\r\nDate: yesterday\r\nReferences: <spoof@example.net>\r\nX-Auto-Response-Suppress: None\r\nContent-Type: text/html\r\nContent-Language: en\r\n\r\n<p>Away</p>\r\n", "text/html", "<p>Away</p>\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := &captureRelayQueue{}
			h := &StandardVacationHandler{Hostname: "mail.example.com", RelayQueue: q}
			script := "require \"vacation\"; vacation :subject \"Away\" :mime text:\n" + strings.ReplaceAll(tc.reason, "\r\n", "\n") + ".\n;"
			e, err := sieveengine.NewSieveExecutorWithExtensions(script, []string{"vacation"})
			if err != nil {
				t.Fatal(err)
			}
			r, err := e.Evaluate(context.Background(), sieveengine.Context{EnvelopeFrom: "sender@example.net", EnvelopeTo: "owner@example.com", Header: map[string][]string{"To": {"owner@example.com"}}, Message: []byte("To: owner@example.com\r\n\r\nhello")})
			if err != nil {
				t.Fatal(err)
			}
			if r.Vacation == nil || !r.Vacation.IsMime {
				t.Fatal("compiled script did not produce a MIME vacation")
			}
			if err := h.HandleVacationResponse(context.Background(), 1, *r.Vacation, vacAddr(t, "sender@example.net"), vacAddr(t, "owner@example.com"), makeMessage(map[string]string{"Message-ID": "<original@example.net>"})); err != nil {
				t.Fatal(err)
			}
			if len(q.calls) != 1 {
				t.Fatalf("queued %d replies", len(q.calls))
			}
			m, err := message.Read(bytes.NewReader(q.calls[0].body))
			if err != nil {
				t.Fatal(err)
			}
			mediaType, _, err := m.Header.ContentType()
			if err != nil {
				t.Fatal(err)
			}
			if mediaType != tc.mediaType {
				t.Fatalf("Content-Type=%q, want %q; wire=%s", mediaType, tc.mediaType, q.calls[0].body)
			}
			for name, want := range map[string]string{"From": "owner@example.com", "To": "sender@example.net", "Subject": "Away", "Auto-Submitted": "auto-replied", "X-Auto-Response-Suppress": "All", "In-Reply-To": "<original@example.net>", "References": "<original@example.net>"} {
				if got := m.Header.Values(name); len(got) != 1 || got[0] != want {
					t.Errorf("%s=%q, want [%q]", name, got, want)
				}
			}
			if !strings.Contains(m.Header.Get("Message-ID"), ".vacation@mail.example.com>") {
				t.Errorf("generated Message-ID replaced: %s", m.Header.Get("Message-ID"))
			}
			if tc.multipart {
				mr := m.MultipartReader()
				if mr == nil {
					t.Fatal("missing multipart reader")
				}
				for _, want := range []string{"Away", "<p>Away</p>"} {
					part, err := mr.NextPart()
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(part.Body)
					if err != nil {
						t.Fatal(err)
					}
					if strings.TrimSpace(string(body)) != want {
						t.Errorf("part=%q,want %q", body, want)
					}
				}
				if _, err := mr.NextPart(); err != io.EOF {
					t.Fatalf("multipart tail: %v", err)
				}
			} else {
				body, err := io.ReadAll(m.Body)
				if err != nil {
					t.Fatal(err)
				}
				if string(body) != tc.body {
					t.Errorf("body=%q,want %q", body, tc.body)
				}
			}
		})
	}
}

func TestVacationMIMEMalformedDoesNotSendOrConsumePeriod(t *testing.T) {
	for _, reason := range []string{
		"not a MIME header\r\n\r\nbody",
		"Content-Type: text/plain; charset=\"broken\r\n\r\nbody",
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: unknown\r\n\r\nbody",
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!notbase64!",
		"Content-Type: multipart/mixed\r\n\r\nbody",
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nbody",
		"Content-Type: text/plain\r\nContent-Type: text/html\r\n\r\nbody",
		"Content-Type: text/plain\r\nContent-Description: a\x00b\r\n\r\nbody",
		"Content-Type: text/plain\r\nContent-Description: caf\xc3\xa9\r\n\r\nbody",
		"Content-Type: text/plain; charset=x-unknown\r\nContent-Transfer-Encoding: bogus-cte\r\n\r\nbody",
		"Content-Type: text/plain; charset=x-unknown\r\nContent-Transfer-Encoding: base64\r\n\r\n!notbase64!",
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b--\r\n",
		"Content-Type: multipart/mixed; boundary=b\r\nContent-Transfer-Encoding: base64\r\n\r\n--b\r\n\r\nbody\r\n--b--\r\n",
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: multipart/mixed; boundary=c\r\n\r\n--c--\r\n--b--\r\n",
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain; charset=x-unknown\r\nContent-Transfer-Encoding: bogus-cte\r\n\r\nbody\r\n--b--\r\n",
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain; charset=x-unknown\r\nContent-Transfer-Encoding: base64\r\n\r\n!notbase64!\r\n--b--\r\n",
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Description: a\x00b\r\n\r\nbody\r\n--b--\r\n",
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nX-Description: caf\xc3\xa9\r\n\r\nbody\r\n--b--\r\n",
	} {
		t.Run(reason, func(t *testing.T) {
			q := &captureRelayQueue{}
			oracle := &fakeVacationOracle{}
			reply := evaluateVacation(t, oracle, "sender@example.net")
			reply.IsMime = true
			reply.Body = reason
			h := &StandardVacationHandler{Hostname: "m", RelayQueue: q}
			err := h.HandleVacationResponse(context.Background(), 42, reply, vacAddr(t, "sender@example.net"), vacAddr(t, "owner@example.com"), makeMessage(nil))
			if err == nil {
				t.Error("malformed MIME accepted")
			}
			if len(q.calls) != 0 || len(oracle.recorded) != 0 {
				t.Errorf("malformed MIME consumed period or was sent: queued=%d recorded=%d", len(q.calls), len(oracle.recorded))
			}
		})
	}
}

func TestVacationMIMEUnknownCharsetPreservesEncoding(t *testing.T) {
	for _, tc := range []struct{ encoding, body string }{
		{"7bit", "Away"},
		{"8bit", "Caf\xe9"},
		{"binary", "Caf\xe9"},
		{"BASE64", "Q2Fm6Q=="},
		{"quoted-printable", "Caf=E9"},
		{"quoted-printable", "abc \t=\r\ndef=00=FF=3D"},
		{"quoted-printable", strings.Repeat("x", 75) + "=\r\ny"},
	} {
		t.Run(tc.encoding, func(t *testing.T) {
			leaf := "Content-Type: text/plain; charset=x-unknown\r\nContent-Transfer-Encoding: " + tc.encoding + "\r\n\r\n" + tc.body + "\r\n"
			for _, reason := range []string{
				leaf,
				"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n" + leaf + "--b--\r\n",
				"Content-Type: message/rfc822\r\n\r\nSubject: Away\r\n" + leaf,
				"Content-Type: multipart/digest; boundary=d\r\n\r\n--d\r\n\r\nSubject: Away\r\n" + leaf + "--d--\r\n",
			} {
				var wire bytes.Buffer
				if err := writeVacationMIME(&wire, message.Header{}, reason); err != nil {
					t.Fatal(err)
				}
				gotBody := strings.SplitN(wire.String(), "\r\n\r\n", 2)[1]
				wantBody := strings.SplitN(reason, "\r\n\r\n", 2)[1]
				if gotBody != wantBody || !strings.Contains(wire.String(), "Content-Transfer-Encoding: "+tc.encoding+"\r\n") {
					t.Fatalf("encoded entity changed: %q", wire.String())
				}
			}
		})
	}
}

func TestVacationMIMEHeaderSizeBound(t *testing.T) {
	large := strings.Repeat("x", 1<<20)
	for _, reason := range []string{
		"X-Large: " + large + "\r\n\r\nAway",
		"Content-Type: message/rfc822\r\n\r\nSubject: " + large + "\r\n\r\nAway",
	} {
		var wire bytes.Buffer
		if err := writeVacationMIME(&wire, message.Header{}, reason); err == nil {
			t.Fatal("oversized MIME header accepted")
		}
	}
	var wire bytes.Buffer
	if err := writeVacationMIME(&wire, message.Header{}, "Content-Type: application/octet-stream\r\n\r\n"+large); err != nil {
		t.Fatalf("body incorrectly limited with headers: %v", err)
	}
}

func TestVacationMIMERejectsInvalidEncodedContent(t *testing.T) {
	for _, body := range []string{"bad=ZZ", "bad=", "bad=A", "bad= \r\n", "bad=af", "bad\x00", "bad\xe9", "bad \r\n", strings.Repeat("x", 77)} {
		for _, charset := range []string{"utf-8", "x-unknown"} {
			leaf := "Content-Type: text/plain; charset=" + charset + "\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" + body
			for _, reason := range []string{leaf, "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n" + leaf + "\r\n--b--\r\n"} {
				t.Run(reason, func(t *testing.T) {
					var wire bytes.Buffer
					if err := writeVacationMIME(&wire, message.Header{}, reason); err == nil {
						t.Fatal("malformed quoted-printable accepted")
					}
					if wire.Len() != 0 {
						t.Fatal("malformed content was partially written")
					}
				})
			}
		}
	}
}

func TestVacationMIMEEncapsulatedMessageValidation(t *testing.T) {
	for _, body := range []string{
		"Subject: Away\r\nContent-Transfer-Encoding: base64\r\n\r\n!notbase64!",
		"Subject: Away\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nbad=ZZ",
		"Subject: caf\xc3\xa9\r\n\r\nAway",
		"Subject: Away\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b--\r\n",
		"Content-Type: text/plain\r\n\r\nNo identifying message header",
	} {
		for _, reason := range []string{
			"Content-Type: message/rfc822\r\n\r\n" + body,
			"Content-Type: multipart/digest; boundary=d\r\n\r\n--d\r\n\r\n" + body + "\r\n--d--\r\n",
		} {
			t.Run(reason, func(t *testing.T) {
				var wire bytes.Buffer
				if err := writeVacationMIME(&wire, message.Header{}, reason); err == nil {
					t.Fatal("invalid encapsulated MIME message accepted")
				}
			})
		}
	}
	for _, encoding := range []string{"base64", "quoted-printable"} {
		reason := "Content-Type: message/rfc822\r\nContent-Transfer-Encoding: " + encoding + "\r\n\r\nU3ViamVjdDogQXdheQ0KDQpBd2F5"
		var wire bytes.Buffer
		if err := writeVacationMIME(&wire, message.Header{}, reason); err == nil {
			t.Errorf("message/rfc822 accepted forbidden %s encoding", encoding)
		}
	}
}
