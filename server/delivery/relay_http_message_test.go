package delivery

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHTTPRelayRequestKeepsMessageBytes: a JSON string is Unicode, and
// json.Marshal replaces every byte that is not valid UTF-8 with U+FFFD. A
// redirected message with 8-bit text in any other charset, in a body, a part of
// a multipart or a raw header value, must still reach the relay API byte for
// byte: in message_base64, with message as it was for relay APIs that do not
// read message_base64. A UTF-8 message is exact in message and its request has
// no message_base64.
func TestHTTPRelayRequestKeepsMessageBytes(t *testing.T) {
	tests := []struct {
		name    string
		message string
		lossy   bool // not valid UTF-8
	}{{
		name:    "8-bit iso-8859-1 single part",
		message: "Subject: test\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\nSch\xf6n\r\n",
		lossy:   true,
	}, {
		name:    "raw 8-bit header value",
		message: "Subject: Sch\xf6n\r\nFrom: sender@example.org\r\n\r\nbody\r\n",
		lossy:   true,
	}, {
		name: "8-bit windows-1251 part of a multipart",
		message: "Subject: x\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
			"--b\r\nContent-Type: text/plain; charset=windows-1251\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" +
			"\xcf\xf0\xe8\xe2\xe5\xf2\r\n" +
			"--b\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAA\r\n" +
			"--b--\r\n",
		lossy: true,
	}, {
		name:    "UTF-8",
		message: "Subject: Schön\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nSchön <&>\r\n",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var body []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var err error
				if body, err = io.ReadAll(r.Body); err != nil {
					t.Errorf("reading relay request: %v", err)
				}
			}))
			defer srv.Close()

			h := &HTTPRelayHandler{HTTPURL: srv.URL}
			if err := h.SendToExternalRelay("sender@example.org", "friend@example.net", []byte(tc.message)); err != nil {
				t.Fatalf("SendToExternalRelay: %v", err)
			}

			// Decoded as a relay API outside this package would.
			var wire struct {
				From          string   `json:"from"`
				Recipients    []string `json:"recipients"`
				Message       string   `json:"message"`
				MessageBase64 *string  `json:"message_base64"`
			}
			if err := json.Unmarshal(body, &wire); err != nil {
				t.Fatalf("decoding the request %q: %v", body, err)
			}
			if wire.From != "sender@example.org" || len(wire.Recipients) != 1 || wire.Recipients[0] != "friend@example.net" {
				t.Errorf("envelope = %q -> %q, want sender@example.org -> [friend@example.net]", wire.From, wire.Recipients)
			}

			if !tc.lossy {
				if wire.MessageBase64 != nil {
					t.Errorf("a UTF-8 message was also sent in message_base64")
				}
				if wire.Message != tc.message {
					t.Errorf("message = %q, want %q", wire.Message, tc.message)
				}
				return
			}

			// message is what it always was: the text with each invalid byte replaced.
			var asBefore string
			b, _ := json.Marshal(tc.message)
			_ = json.Unmarshal(b, &asBefore)
			if wire.Message != asBefore {
				t.Errorf("message = %q, want %q (unchanged for relay APIs that do not read message_base64)", wire.Message, asBefore)
			}
			if wire.MessageBase64 == nil {
				t.Fatalf("no message_base64: the relay API received only %q, the message was %q", wire.Message, tc.message)
			}
			got, err := base64.StdEncoding.DecodeString(*wire.MessageBase64)
			if err != nil {
				t.Fatalf("message_base64 is not standard base64: %v", err)
			}
			if string(got) != tc.message {
				t.Errorf("message_base64 decodes to %q, want %q", got, tc.message)
			}
		})
	}
}
