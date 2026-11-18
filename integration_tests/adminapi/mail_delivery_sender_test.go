//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/adminapi"
)

// senderCase is a sender handed to /admin/mail/deliver and the envelope sender Sieve
// and vacation must see for it. An empty want means the sender does not parse: a named
// "from" is refused with 400 Invalid sender (#1995), while a From: header fallback is
// ignored and the message delivered with no envelope sender, so vacation does not reply.
type senderCase struct {
	name, from, want string
	notJSON          bool // invalid UTF-8, which a JSON string cannot carry
}

// explicitSenders are written in RFC 5321 §4.1.2 syntax, as a caller writes "from":
// a quoted local part is decoded exactly once, and a bare `"` outside a whole quoted
// string, or an escape that splits a UTF-8 sequence, does not parse.
var explicitSenders = []senderCase{
	{name: "consecutive dots", from: "first..last@example.com", want: "first..last@example.com"},
	{name: "second at sign", from: "a@b.example@example.com", want: `"a@b.example"@example.com`},
	{name: "surrounding whitespace", from: " sender@example.org ", want: "sender@example.org"},
	{name: "local part case", from: `John.Doe@Example.com`, want: `John.Doe@example.com`},
	{name: "quoted local part", from: `"John Doe"@example.com`, want: `"John Doe"@example.com`},
	{name: "quoted dot-string", from: `"John.Doe"@example.com`, want: `John.Doe@example.com`},
	{name: "needless quoted pair", from: `"J\ohn"@example.com`, want: `John@example.com`},
	{name: "quoted at sign", from: `"a@b.example"@example.com`, want: `"a@b.example"@example.com`},
	{name: "escaped quote", from: `"a\"b"@example.com`, want: `"a\"b"@example.com`},
	{name: "escaped backslash", from: `"a\\b"@example.com`, want: `"a\\b"@example.com`},
	{name: "quoted edge spaces", from: `" sender "@example.com`, want: `" sender "@example.com`},
	{name: "literal surrounding quotes", from: `"\"Sender\""@example.com`, want: `"\"Sender\""@example.com`},
	{name: "unquoted space", from: `John Doe@example.com`},
	{name: "bare quote inside", from: `Sen"der@example.com`},
	{name: "bare quote at end", from: `Sender"@example.com`},
	{name: "unterminated quote", from: `"Sender@example.com`},
	{name: "escaped closing quote", from: `"Sender\"@example.com`},
	{name: "quoted string then at signs", from: `"a"@b@example.com`},
	{name: "escape splits UTF-8", from: "\"\xc3\\\xa9\"@example.com", notJSON: true},
}

// headerSenders are From: header fields. net/mail has already decoded the mailbox, so
// nothing in it is trimmed or unquoted again.
var headerSenders = []senderCase{
	{name: "quoted local part", from: `Sender <"John Doe"@example.com>`, want: `"John Doe"@example.com`},
	{name: "quoted edge spaces", from: `" sender "@example.com`, want: `" sender "@example.com`},
	{name: "literal surrounding quotes", from: `"\"sender\""@example.com`, want: `"\"sender\""@example.com`},
	{name: "quoted at sign", from: `"a@b.example"@example.com`, want: `"a@b.example"@example.com`},
	{name: "local part case", from: `John.Doe@Example.com`, want: `John.Doe@example.com`},
}

// TestAdminAPI_DeliverMail_SenderReadAsReversePath is #1970: /admin/mail/deliver reads
// its sender as an envelope sender, not as a login name. A local part with consecutive
// dots is a sender go-smtp hands on (#1907), and a second "@" can only come from a quoted
// local part, never from a master-token suffix (#1938). The local part keeps its case
// (#2101). An explicit "from" (JSON, query, form or X-From) is in its written form and
// is decoded once; the From: header fallback is already decoded by net/mail and is not
// decoded or trimmed again. The serialized `"John Doe"@example.com` and the From: field
// naming the same mailbox reach the same sender. Every explicit case runs through both
// the request check (#1995) and delivery, which must agree: what the check lets
// through is delivered with exactly that sender, and nothing else is delivered.
func TestAdminAPI_DeliverMail_SenderReadAsReversePath(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rq := &captureRelay{}
	server, _ := setupHTTPAPIServerWithOptions(t, func(o *adminapi.ServerOptions) {
		o.RelayQueue = rq
	})
	defer server.Close()

	for _, tc := range explicitSenders {
		formats := []string{"json", "query", "form", "X-From"}
		if tc.notJSON {
			formats = formats[1:]
		}
		for _, format := range formats {
			t.Run("from/"+tc.name+"/"+format, func(t *testing.T) {
				checkDeliverySender(t, server, rq, format, tc, "sender@example.net")
			})
		}
	}
	for _, tc := range headerSenders {
		t.Run("From header/"+tc.name, func(t *testing.T) {
			checkDeliverySender(t, server, rq, "", tc, tc.from)
		})
	}
}

// checkDeliverySender delivers one message with the sender in format ("" for none, so
// the From: header is the fallback) and checks the vacation reply goes to tc.want.
func checkDeliverySender(t *testing.T, server *HTTPAPITestServer, rq *captureRelay, format string, tc senderCase, fromHeader string) {
	t.Helper()
	ctx := context.Background()
	marker := fmt.Sprintf("sender-%d", time.Now().UnixNano())
	email := fmt.Sprintf("apisender-%s@example.com", marker)
	createDeliveryAccount(t, server, email)
	accountID, err := server.rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatalf("lookup account: %v", err)
	}
	// With no envelope sender vacation never replies, so an unconditional vacation
	// shows a sender that should not parse but was used anyway.
	script := "require [\"vacation\"];\r\nvacation \"I am away.\";\r\n"
	if tc.want != "" {
		script = "require [\"envelope\", \"vacation\"];\r\n" +
			"if envelope :all :is \"from\" " + sieveString(tc.want) + " {\r\n" +
			"  vacation \"I am away.\";\r\n}\r\n"
	}
	sc, err := server.rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
	if err != nil {
		t.Fatalf("create sieve script: %v", err)
	}
	if err := server.rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
		t.Fatalf("activate sieve script: %v", err)
	}

	before := len(rq.snapshot())
	message := "From: " + fromHeader + "\r\nTo: " + email + "\r\nSubject: who sent this\r\n" +
		"Message-ID: <" + marker + "@example.net>\r\n\r\nbody\r\n"
	resp, body := deliverWithSender(t, server, format, tc.from, email, message)
	if tc.want == "" && format != "" {
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "Invalid sender") {
			t.Errorf("sender %q does not parse: deliver %d %s, want 400 Invalid sender", tc.from, resp.StatusCode, body)
		}
		if n := len(rq.snapshot()) - before; n != 0 {
			t.Errorf("sender %q does not parse, but %d relay items were queued", tc.from, n)
		}
		return
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deliver: %d %s", resp.StatusCode, string(body))
	}

	var replies []string
	for _, it := range rq.snapshot()[before:] {
		if it.msgType == "vacation" {
			replies = append(replies, it.to)
		}
	}
	if tc.want == "" {
		if len(replies) != 0 {
			t.Errorf("sender %q does not parse, but vacation replied to %q", tc.from, replies)
		}
	} else if len(replies) != 1 || replies[0] != tc.want {
		t.Errorf("sender %q: vacation replies to %q, want one to %q (Sieve must see that envelope sender)", tc.from, replies, tc.want)
	}
}

// deliverWithSender posts message to /admin/mail/deliver with from in format: the JSON
// "from" field, the "from" query parameter, a multipart "from" field or the X-From
// header. An empty format sends no sender.
func deliverWithSender(t *testing.T, s *HTTPAPITestServer, format, from, recipient, message string) (*http.Response, []byte) {
	t.Helper()
	switch format {
	case "", "json":
		body := map[string]any{"recipients": []string{recipient}, "message": message}
		if format == "json" {
			body["from"] = from
		}
		return s.makeRequest(t, http.MethodPost, "/admin/mail/deliver", body)
	}
	endpoint := s.URL + "/admin/mail/deliver"
	var body bytes.Buffer
	contentType := "message/rfc822"
	header := http.Header{}
	switch format {
	case "form":
		mw := multipart.NewWriter(&body)
		for _, kv := range [][2]string{{"recipients", recipient}, {"from", from}, {"message", message}} {
			if err := mw.WriteField(kv[0], kv[1]); err != nil {
				t.Fatal(err)
			}
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}
		contentType = mw.FormDataContentType()
	case "query":
		body.WriteString(message)
		endpoint += "?" + url.Values{"recipients": {recipient}, "from": {from}}.Encode()
	case "X-From":
		body.WriteString(message)
		endpoint += "?" + url.Values{"recipients": {recipient}}.Encode()
		header.Set("X-From", from)
	default:
		t.Fatalf("unknown sender format %q", format)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, &body)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, respBody
}

// sieveString quotes s as a Sieve quoted string (RFC 5228 §2.4.2).
func sieveString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func (q *captureRelay) snapshot() []capturedRelayItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]capturedRelayItem(nil), q.items...)
}
