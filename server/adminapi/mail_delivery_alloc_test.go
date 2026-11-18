package adminapi

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/migadu/sora/server"
)

// TestDeliverMailCopiesAreCharged (#2111, #2120): /admin/mail/deliver must not
// make message-sized allocations the delivery memory budget never sees, in any
// request form. A raw body is the message as read; a multipart message part
// (file or form value) is read once from the stream into a buffer charged
// before it grows; a JSON message is decoded straight into a buffer charged
// before it is allocated. A refusal test cannot show an uncharged allocation
// (the delivery still fits), so the test measures allocations.
//
// The handler runs on a node without an upload worker, so it parses the whole
// request and answers 503 before any delivery. runtime.MemStats.TotalAlloc
// around it is what it allocated; SessionMemoryTracker.TotalAllocated is what it
// charged (every charge, freed or not). The allowance covers headers, readers
// and bookkeeping and is well under one ~60 KiB copy of the message.
func TestDeliverMailCopiesAreCharged(t *testing.T) {
	// Include architecture/race-dependent bookkeeping while staying below one full
	// ~60 KiB message copy. The pre-fix raw/file paths still fail this bound.
	const allowance = 48 << 10
	message := "From: sender@example.com\r\nTo: user@example.com\r\nSubject: copies\r\n\r\n" +
		strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop\r\n", (60<<10)/64)

	multipartBody := func(file bool) (string, []byte) {
		var b bytes.Buffer
		mw := multipart.NewWriter(&b)
		if err := mw.WriteField("recipients", "user@example.com"); err != nil {
			t.Fatal(err)
		}
		if file {
			fw, err := mw.CreateFormFile("message", "message.eml")
			if err != nil {
				t.Fatal(err)
			}
			fw.Write([]byte(message))
		} else if err := mw.WriteField("message", message); err != nil {
			t.Fatal(err)
		}
		mw.Close()
		return mw.FormDataContentType(), b.Bytes()
	}
	fileType, fileBody := multipartBody(true)
	valueType, valueBody := multipartBody(false)
	jsonBody, err := json.Marshal(map[string]any{"recipients": []string{"user@example.com"}, "message": message})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, contentType, target string
		body                      []byte
	}{
		{"raw message/rfc822", "message/rfc822", "/admin/mail/deliver?recipients=user@example.com", []byte(message)},
		{"multipart file", fileType, "/admin/mail/deliver", fileBody},
		{"multipart form value", valueType, "/admin/mail/deliver", valueBody},
		{"json", "application/json", "/admin/mail/deliver", jsonBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const runs = 5
			var allocated, charged int64
			for range runs {
				budget := server.NewSessionMemoryTracker(0)
				s := &Server{deliveryMemory: budget}
				req := httptest.NewRequest("POST", tc.target, bytes.NewReader(tc.body))
				req.Header.Set("Content-Type", tc.contentType)
				rec := httptest.NewRecorder()

				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				s.handleDeliverMail(rec, req)
				runtime.ReadMemStats(&after)

				if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "no upload worker") {
					t.Fatalf("status %d %s; want the 503 for a node without an upload worker, after the request was parsed", rec.Code, rec.Body.String())
				}
				if budget.Current() != 0 {
					t.Fatalf("the request left %d bytes charged", budget.Current())
				}
				allocated += int64(after.TotalAlloc - before.TotalAlloc)
				charged += budget.TotalAllocated()
			}
			allocated, charged = allocated/runs, charged/runs
			if allocated > charged+allowance {
				t.Errorf("allocated %d bytes for a %d-byte message but charged %d: %d bytes were never charged (allowance %d)",
					allocated, len(message), charged, allocated-charged, allowance)
			}
		})
	}
}
