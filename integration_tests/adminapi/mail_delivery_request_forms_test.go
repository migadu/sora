//go:build integration

package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestAdminAPI_DeliverMail_RequestFormsByteForByte: every request form of
// /admin/mail/deliver stores the message it was given byte for byte below the
// trace headers: a raw message/rfc822 body, a JSON "message" string (written
// by encoding/json, and with every escape form JSON allows), and a
// multipart/form-data "message" part, as a form value or a file upload, before
// or after the other fields.
func TestAdminAPI_DeliverMail_RequestFormsByteForByte(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	type request struct {
		contentType, query string
		body               []byte
	}
	multipartRequest := func(msg, email string, asFile, messageFirst bool) request {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		writeMessage := func() {
			if asFile {
				fw, err := mw.CreateFormFile("message", "message.eml")
				if err != nil {
					t.Fatal(err)
				}
				fw.Write([]byte(msg))
			} else {
				mw.WriteField("message", msg)
			}
		}
		if messageFirst {
			writeMessage()
		}
		mw.WriteField("recipients", email)
		mw.WriteField("from", "sender@example.com")
		if !messageFirst {
			writeMessage()
		}
		mw.Close()
		return request{contentType: mw.FormDataContentType(), body: body.Bytes()}
	}
	// escapeEverything writes msg as a JSON string with every character as a \u
	// escape (a surrogate pair above the BMP), and the short escapes where JSON has them.
	escapeEverything := func(msg string) string {
		var b strings.Builder
		b.WriteByte('"')
		for _, r := range msg {
			switch {
			case r == '\r':
				b.WriteString(`\r`)
			case r == '\n':
				b.WriteString(`\n`)
			case r == '\t':
				b.WriteString(`\t`)
			case r == '/':
				b.WriteString(`\/`)
			case r > 0xFFFF:
				r -= 0x10000
				fmt.Fprintf(&b, `\u%04x\u%04X`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
			default:
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		}
		b.WriteByte('"')
		return b.String()
	}

	for _, tc := range []struct {
		name  string
		build func(msg, email string) request
	}{
		{"raw message/rfc822", func(msg, email string) request {
			return request{contentType: "message/rfc822", query: "?recipients=" + email, body: []byte(msg)}
		}},
		{"json", func(msg, email string) request {
			body, err := json.Marshal(map[string]any{"recipients": []string{email}, "message": msg, "unknown_field": map[string]any{"ignored": true}})
			if err != nil {
				t.Fatal(err)
			}
			return request{contentType: "application/json", body: body}
		}},
		{"json, every character escaped", func(msg, email string) request {
			return request{contentType: "application/json", body: []byte(`{"message":` + escapeEverything(msg) + `,"recipients":["` + email + `"]}`)}
		}},
		{"multipart form value", func(msg, email string) request { return multipartRequest(msg, email, false, false) }},
		{"multipart form value, message first", func(msg, email string) request { return multipartRequest(msg, email, false, true) }},
		{"multipart file upload", func(msg, email string) request { return multipartRequest(msg, email, true, false) }},
		{"multipart file upload, message first", func(msg, email string) request { return multipartRequest(msg, email, true, true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, tempDir := setupHTTPAPIServerWithUploader(t)
			defer server.Close()
			email := fmt.Sprintf("apiforms-%d@example.com", time.Now().UnixNano())
			createDeliveryAccount(t, server, email)

			msg := "From: sender@example.com\r\nTo: " + email + "\r\nSubject: request forms\r\n" +
				"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" +
				"quote \" backslash \\ slash / tab \t ünïcödé 日本語 😀\r\n" +
				strings.Repeat("line of the body\r\n", 3000)
			rq := tc.build(msg, email)
			req, err := http.NewRequest("POST", server.URL+"/admin/mail/deliver"+rq.query, bytes.NewReader(rq.body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", rq.contentType)
			req.Header.Set("Authorization", "Bearer "+testAPIKey)
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("deliver: %d %s", resp.StatusCode, respBody)
			}

			time.Sleep(300 * time.Millisecond)
			stored := readStoredAdminMessage(t, tempDir)
			if !strings.HasSuffix(stored, msg) {
				t.Fatalf("stored message does not end with the delivered one (stored %d bytes, delivered %d)", len(stored), len(msg))
			}
		})
	}
}
