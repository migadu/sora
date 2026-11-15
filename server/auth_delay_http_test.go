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
//
// Both listeners serve HTTP/2 over TLS (ServeTLS), where WriteTimeout is a per-stream
// timer that resets the stream and cancels the request when it fires: moved only after
// the wait, it would end a delayed login during the wait. HTTP/1.1 alone would not show
// that, as its write deadline only fails the writes.
func TestApplyHTTPAuthenticationDelay_MovesTheWriteDeadlinePastTheDelay(t *testing.T) {
	const (
		writeTimeout = 100 * time.Millisecond
		delay        = 300 * time.Millisecond
		budget       = 500 * time.Millisecond
	)
	for _, tc := range []struct {
		proto string
		http2 bool
	}{{"HTTP/1.1", false}, {"HTTP/2.0", true}} {
		t.Run(tc.proto, func(t *testing.T) {
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
			if tc.http2 {
				ts.EnableHTTP2 = true
				ts.StartTLS()
			} else {
				ts.Start()
			}
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
				if resp.Proto != tc.proto {
					t.Errorf("served over %s, want %s", resp.Proto, tc.proto)
				}
				body, err := io.ReadAll(resp.Body)
				return string(body), err
			}

			if body, err := post(0); err != nil || body != "answered" {
				t.Fatalf("answer written right after a %v delay, past WriteTimeout %v: got %q, error %v; want it delivered", delay, writeTimeout, body, err)
			}
			if body, err := post(2 * budget); err == nil {
				t.Fatalf("answer written %v after the delay, past its budget %v, reached the client: %q", 2*budget, budget, body)
			}
		})
	}
}
