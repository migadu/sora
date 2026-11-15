package userapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
)

// A login the rate limit delays waits inside the handler, after net/http has set the
// request's read and write deadlines (ReadTimeout and WriteTimeout, from when it read the
// request). A delay as long as them (max_delay and both timeouts are 30 s by default) ran
// past both: the read deadline cancelled the request and the write deadline dropped the
// answer, so the client got no response at all, not even for the right password (#1074).
// The server's timeouts are scaled down here and the delay outlasts them.
func TestDelayedLoginIsAnsweredPastTheServerTimeouts(t *testing.T) {
	origCost := db.BcryptCost
	db.BcryptCost = bcrypt.MinCost
	t.Cleanup(func() { db.BcryptCost = origCost })

	const delay = 400 * time.Millisecond
	limiter := server.NewAuthRateLimiter("user-api", "delay-deadline", "", server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 100,
		IPUsernameBlockDuration:  time.Hour,
		IPUsernameWindowDuration: time.Hour,
		MaxAttemptsPerIP:         100,
		IPBlockDuration:          time.Hour,
		IPWindowDuration:         time.Hour,
		DelayStartThreshold:      1,
		InitialDelay:             delay,
		MaxDelay:                 delay,
		DelayMultiplier:          2,
		CleanupInterval:          time.Hour,
	})
	t.Cleanup(limiter.Stop)

	// s.rdb is nil: the login names no account (an invalid address), so it is answered
	// 401 after a dummy verification, without the database.
	s := &Server{name: "delay-deadline", authLimiter: limiter}
	s.settings.Store(&reloadableSettings{})
	ts := httptest.NewUnstartedServer(s.SetupRoutes())
	ts.Config.ReadTimeout = delay / 4
	ts.Config.WriteTimeout = delay / 4
	ts.Start()
	t.Cleanup(ts.Close)
	client := ts.Client()
	client.Timeout = 10 * time.Second

	// One failed login from the client's address: its next login waits delay.
	clientAddr := &server.StringAddr{Addr: "127.0.0.1"}
	limiter.RecordAuthAttempt(t.Context(), clientAddr, "user@example.com", false)
	if got := limiter.GetAuthenticationDelay(clientAddr); got != delay {
		t.Fatalf("setup: delay %v, want %v", got, delay)
	}

	start := time.Now()
	resp, err := client.Post(ts.URL+"/user/auth/login", "application/json",
		strings.NewReader(`{"email":"not-an-address","password":"wrong-password"}`))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("delayed login got no answer after %v: %v", elapsed.Round(time.Millisecond), err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the answer: %v", err)
	}
	var body map[string]string
	if resp.StatusCode != http.StatusUnauthorized || json.Unmarshal(raw, &body) != nil || body["error"] != "Invalid credentials" {
		t.Fatalf("delayed login: status %d %q, want 401 Invalid credentials", resp.StatusCode, raw)
	}
	if elapsed < delay {
		t.Errorf("answered after %v, before the %v delay", elapsed, delay)
	}
}
