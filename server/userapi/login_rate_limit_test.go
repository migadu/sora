package userapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// TestLoginFromBlockedIPIsRefused verifies that a login with the right password is
// refused while its source address is blocked, and that it does not lift the block.
// Regression test for #351: a login answered from the auth cache (which the User API no
// longer has) skipped CanAttemptAuth and recorded a success, which deleted the address's
// block. The server has no database, so a refused login must be answered before the
// handler reaches it.
func TestLoginFromBlockedIPIsRefused(t *testing.T) {
	const clientIP = "203.0.113.7"
	limiter := server.NewAuthRateLimiter("user-api", "test", "", server.AuthRateLimiterConfig{
		Enabled:          true,
		MaxAttemptsPerIP: 3,
		IPBlockDuration:  time.Hour,
		IPWindowDuration: time.Hour,
		CleanupInterval:  time.Hour,
	})
	defer limiter.Stop()
	clientAddr := &server.StringAddr{Addr: clientIP}
	for i := 0; i < 3; i++ {
		limiter.RecordAuthAttempt(context.Background(), clientAddr, fmt.Sprintf("guess%d@example.com", i), false)
	}
	if !limiter.IsIPBlocked(clientAddr) {
		t.Fatal("setup: address is not blocked")
	}

	s := &Server{name: "test", authLimiter: limiter}
	req := httptest.NewRequest(http.MethodPost, "/user/auth/login",
		strings.NewReader(`{"email":"user@example.com","password":"secret"}`))
	req.RemoteAddr = clientIP + ":40000"
	rec := httptest.NewRecorder()

	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("the login of a blocked address went on to the database: %v", p)
			}
		}()
		s.handleLogin(rec, req)
	}()

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("login from a blocked address: status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if !limiter.IsIPBlocked(clientAddr) {
		t.Error("the login lifted the address's block")
	}
}
