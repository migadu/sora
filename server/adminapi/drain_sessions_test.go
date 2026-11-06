package adminapi

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// A mail delivery counts as a drain session from the moment the request is handled
// until it returns, however it ends.
func TestDrainSessionsCountDeliveriesInFlight(t *testing.T) {
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
	for s.DrainSessions() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("delivery reading its body is not counted as open")
		}
		time.Sleep(5 * time.Millisecond)
	}

	sender.CloseWithError(errors.New("client went away"))
	<-done
	if open := s.DrainSessions(); open != 0 {
		t.Fatalf("after the delivery: %d open, want 0", open)
	}
}

// A backend refusing new sessions (in maintenance, past refuse_after) refuses deliveries
// with 503 and Retry-After before reading them, and does not count them.
func TestDeliverMailRefusedInMaintenance(t *testing.T) {
	s := &Server{maintenanceGate: server.NewMaintenanceGate(true)}
	req := httptest.NewRequest("POST", "/admin/mail/deliver", strings.NewReader("Subject: hi\r\n\r\nhi\r\n"))
	req.Header.Set("Content-Type", "message/rfc822")
	rec := httptest.NewRecorder()

	s.handleDeliverMail(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("delivery while refusing: %d, Retry-After %q; want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
	if open := s.DrainSessions(); open != 0 {
		t.Fatalf("a refused delivery is counted: %d open", open)
	}
}
