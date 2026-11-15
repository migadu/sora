package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ApplyHTTPAuthenticationDelay moves the write deadline past the delay: an answer
// written after a delay longer than the server's WriteTimeout reaches the client
// (#1074). The deadline stays bounded: an answer later than the delay plus budget is
// dropped, as one later than WriteTimeout is without a delay.
func TestApplyHTTPAuthenticationDelay_MovesTheWriteDeadlinePastTheDelay(t *testing.T) {
	const (
		writeTimeout = 100 * time.Millisecond
		delay        = 300 * time.Millisecond
		budget       = 500 * time.Millisecond
	)
	limiter := &MockAuthDelayHelper{delay: delay}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := ApplyHTTPAuthenticationDelay(r.Context(), w, limiter, &StringAddr{Addr: "192.0.2.10:4000"}, "userapi", budget); err != nil {
			t.Errorf("delay: %v", err)
			return
		}
		stall, _ := time.ParseDuration(r.URL.Query().Get("stall"))
		time.Sleep(stall)
		_, _ = io.WriteString(w, "answered")
	}))
	ts.Config.WriteTimeout = writeTimeout
	ts.Start()
	t.Cleanup(ts.Close)
	client := ts.Client()
	client.Timeout = 10 * time.Second

	// POST: the client does not replay it on a reused connection the server closed.
	post := func(stall time.Duration) (string, error) {
		resp, err := client.Post(ts.URL+"/?stall="+stall.String(), "text/plain", strings.NewReader("login"))
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}

	if body, err := post(0); err != nil || body != "answered" {
		t.Fatalf("answer written right after a %v delay, past WriteTimeout %v: got %q, error %v; want it delivered", delay, writeTimeout, body, err)
	}
	if body, err := post(2 * budget); err == nil {
		t.Fatalf("answer written %v after the delay, past its budget %v, reached the client: %q", 2*budget, budget, body)
	}
}
