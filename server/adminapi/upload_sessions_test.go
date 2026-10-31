package adminapi

import (
	"errors"
	"io"
	"net/http/httptest"
	"testing"
	"time"
)

// A mail delivery counts as an upload session from the moment the request is handled
// until it returns, however it ends; started never goes back.
func TestUploadSessionsCountDeliveriesInFlight(t *testing.T) {
	s := &Server{}
	body, sender := io.Pipe()
	req := httptest.NewRequest("POST", "/admin/mail/deliver", body)
	req.Header.Set("Content-Type", "message/rfc822")

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.handleDeliverMail(httptest.NewRecorder(), req)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for open, _ := s.UploadSessions(); open != 1; open, _ = s.UploadSessions() {
		if time.Now().After(deadline) {
			t.Fatal("delivery reading its body is not counted as open")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, started := s.UploadSessions(); started != 1 {
		t.Fatalf("started = %d during the delivery, want 1", started)
	}

	sender.CloseWithError(errors.New("client went away"))
	<-done
	if open, started := s.UploadSessions(); open != 0 || started != 1 {
		t.Fatalf("after the delivery: %d open, %d started; want 0 open, 1 started", open, started)
	}
}
