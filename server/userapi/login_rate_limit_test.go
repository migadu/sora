package userapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server"
)

// TestCachedLoginFromBlockedIPIsRefused verifies that a login answered from the auth
// cache is refused while its source address is blocked, and that it does not lift the
// block. Regression test for #351: the cache shortcut ran before CanAttemptAuth and
// recorded a success, which deleted the address's block. The server has no database,
// so a refused login must be answered before the handler reaches it.
func TestCachedLoginFromBlockedIPIsRefused(t *testing.T) {
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

	cache := lookupcache.New(5*time.Minute, time.Minute, 100, 5*time.Minute, 30*time.Second)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = cache.Stop(ctx)
	})
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cache.SetSuccess("user@example.com", 42, string(hash), "secret")
	if _, found, _ := cache.Authenticate("user@example.com", "secret"); !found {
		t.Fatal("setup: the login is not answered from the cache")
	}

	s := &Server{name: "test", authCache: cache, authLimiter: limiter}
	req := httptest.NewRequest(http.MethodPost, "/user/auth/login",
		strings.NewReader(`{"email":"user@example.com","password":"secret"}`))
	req.RemoteAddr = clientIP + ":40000"
	rec := httptest.NewRecorder()

	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("the login of a blocked address went on past the auth cache to the database: %v", p)
			}
		}()
		s.handleLogin(rec, req)
	}()

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("cached login from a blocked address: status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if !limiter.IsIPBlocked(clientAddr) {
		t.Error("the cached login lifted the address's block")
	}
}
