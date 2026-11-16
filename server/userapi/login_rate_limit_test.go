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

// A blocked login must be refused before any credential work and must not clear
// its source block. With no database configured, reaching it panics and fails.
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
				t.Errorf("the login of a blocked address reached the database: %v", p)
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
