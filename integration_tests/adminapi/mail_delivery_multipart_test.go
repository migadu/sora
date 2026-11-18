//go:build integration

package httpapi

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestAdminAPI_DeliverMail_MultipartMessage: a multipart/form-data delivery
// stores the message given as the "message" form value, or as a "message" file
// upload, byte for byte below the trace headers (#2111 reads the file straight
// into the delivered buffer).
func TestAdminAPI_DeliverMail_MultipartMessage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	for _, asFile := range []bool{false, true} {
		name := "form value"
		if asFile {
			name = "file upload"
		}
		t.Run(name, func(t *testing.T) {
			server, tempDir := setupHTTPAPIServerWithUploader(t)
			defer server.Close()
			email := fmt.Sprintf("apimultipart-%d@example.com", time.Now().UnixNano())
			createDeliveryAccount(t, server, email)

			marker := fmt.Sprintf("multipart-%d", time.Now().UnixNano())
			msg := "From: sender@example.com\r\nTo: " + email + "\r\nSubject: " + marker + "\r\n\r\n" +
				strings.Repeat("line of the multipart body\r\n", 3000)
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			mw.WriteField("recipients", email)
			if asFile {
				fw, err := mw.CreateFormFile("message", "message.eml")
				if err != nil {
					t.Fatal(err)
				}
				fw.Write([]byte(msg))
			} else {
				mw.WriteField("message", msg)
			}
			mw.Close()

			req, err := http.NewRequest("POST", server.URL+"/admin/mail/deliver", &body)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", mw.FormDataContentType())
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
