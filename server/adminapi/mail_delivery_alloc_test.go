package adminapi

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/migadu/sora/server"
)

// TestDeliverMailCopiesAreCharged (#2111): /admin/mail/deliver must not make
// message-sized copies the delivery memory budget never sees. A raw body is the
// message as read (no string round-trip), and a multipart file upload is read
// once into a buffer charged before it grows (no io.ReadAll, no string, no
// second []byte). A refusal test cannot show an uncharged copy (the delivery
// still fits), so the test measures allocations.
//
// The handler runs on a node without an upload worker, so it parses the whole
// request and answers 503 before any delivery. runtime.MemStats.TotalAlloc
// around it is what it allocated; SessionMemoryTracker.TotalAllocated is what it
// charged (every charge, freed or not). The allowance covers headers, readers
// and bookkeeping and is well under one ~60 KiB copy of the message.
//
// ParseMultipartForm's own buffering of the form is charged as the octets it
// reads, an approximation: its buffer grows by doubling. So for the multipart
// case the parser's allocation for the same body is measured on its own, and
// only what the handler allocates beyond it has to be charged beyond the octets.
func TestDeliverMailCopiesAreCharged(t *testing.T) {
	const allowance = 24 << 10
	message := "From: sender@example.com\r\nTo: user@example.com\r\nSubject: copies\r\n\r\n" +
		strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop\r\n", (60<<10)/64)

	var form bytes.Buffer
	mw := multipart.NewWriter(&form)
	if err := mw.WriteField("recipients", "user@example.com"); err != nil {
		t.Fatal(err)
	}
	fw, err := mw.CreateFormFile("message", "message.eml")
	if err != nil {
		t.Fatal(err)
	}
	fw.Write([]byte(message))
	mw.Close()

	const runs = 5
	measure := func(t *testing.T, contentType, target string, body []byte, run func(*httptest.ResponseRecorder, *http.Request, *Server)) (allocated, charged int64) {
		t.Helper()
		for range runs {
			budget := server.NewSessionMemoryTracker(0)
			s := &Server{deliveryMemory: budget}
			req := httptest.NewRequest("POST", target, bytes.NewReader(body))
			req.Header.Set("Content-Type", contentType)
			rec := httptest.NewRecorder()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			run(rec, req, s)
			runtime.ReadMemStats(&after)
			allocated += int64(after.TotalAlloc - before.TotalAlloc)
			charged += budget.TotalAllocated()
			if budget.Current() != 0 {
				t.Fatalf("the request left %d bytes charged", budget.Current())
			}
		}
		return allocated / runs, charged / runs
	}
	handle := func(t *testing.T) func(*httptest.ResponseRecorder, *http.Request, *Server) {
		return func(rec *httptest.ResponseRecorder, req *http.Request, s *Server) {
			s.handleDeliverMail(rec, req)
			if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "no upload worker") {
				t.Fatalf("status %d %s; want the 503 for a node without an upload worker, after the request was parsed", rec.Code, rec.Body.String())
			}
		}
	}

	t.Run("raw message/rfc822 is the bytes read", func(t *testing.T) {
		allocated, charged := measure(t, "message/rfc822", "/admin/mail/deliver?recipients=user@example.com", []byte(message), handle(t))
		if allocated > charged+allowance {
			t.Errorf("allocated %d bytes for a %d-byte message but charged %d: %d bytes were never charged (allowance %d)",
				allocated, len(message), charged, allocated-charged, allowance)
		}
	})

	t.Run("multipart file is read once, charged", func(t *testing.T) {
		parserAllocated, _ := measure(t, mw.FormDataContentType(), "/admin/mail/deliver", form.Bytes(),
			func(_ *httptest.ResponseRecorder, req *http.Request, _ *Server) {
				if err := req.ParseMultipartForm(32 << 20); err != nil {
					t.Fatal(err)
				}
			})
		allocated, charged := measure(t, mw.FormDataContentType(), "/admin/mail/deliver", form.Bytes(), handle(t))
		beyondParser := allocated - parserAllocated
		chargedBeyondOctets := charged - int64(form.Len())
		if beyondParser > chargedBeyondOctets+allowance {
			t.Errorf("beyond the form parser (%d bytes), the handler allocated %d bytes for a %d-byte message but charged %d beyond the body's octets: %d bytes were never charged (allowance %d)",
				parserAllocated, beyondParser, len(message), chargedBeyondOctets, beyondParser-chargedBeyondOctets, allowance)
		}
	})
}
