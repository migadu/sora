package userapiproxy

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// SIGHUP runs ReloadConfig on its own goroutine while requests are served: every
// request's token is checked against the jwt_secret it replaces.
func TestReloadConfig_DuringTokenValidation(t *testing.T) {
	secretA, secretB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := New(ctx, &resilient.ResilientDatabase{}, ServerOptions{
		Name:        "reload",
		RemoteAddrs: []string{"127.0.0.1:1"},
		JWTSecret:   secretA,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{
		Email:            "user@example.com",
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
	}).SignedString([]byte(secretA))
	if err != nil {
		t.Fatal(err)
	}

	cfgs := []config.ServerConfig{
		{Name: "reload", JWTSecret: secretB},
		{Name: "reload", JWTSecret: secretA},
	}
	reloadWhile(t, s.ReloadConfig, cfgs, func() {
		for i := 0; i < 200; i++ {
			_, _ = s.validateToken(tok) // valid or not depending on the reload it meets
		}
	})

	// A reload takes effect for the requests after it.
	if err := s.ReloadConfig(config.ServerConfig{Name: "reload", JWTSecret: secretB}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.validateToken(tok); err == nil {
		t.Error("a token signed with the replaced jwt_secret still validates")
	}

	// A secret New would refuse is not taken on reload either.
	if err := s.ReloadConfig(config.ServerConfig{Name: "reload", JWTSecret: secretA}); err != nil {
		t.Fatal(err)
	}
	// Refused loudly: the caller logs a failed reload naming the secret, never its value.
	if err := s.ReloadConfig(config.ServerConfig{Name: "reload", JWTSecret: "short"}); err == nil || !strings.Contains(err.Error(), "jwt_secret") || strings.Contains(err.Error(), "short") {
		t.Errorf("reloading a too-short jwt_secret: error %v, want one naming jwt_secret without its value", err)
	}
	if _, err := s.validateToken(tok); err != nil {
		t.Errorf("a too-short jwt_secret replaced the secret: %v", err)
	}
}

// reloadWhile runs ReloadConfig every millisecond, alternating cfgs, until work returns.
func reloadWhile(t *testing.T, reload func(config.ServerConfig) error, cfgs []config.ServerConfig, work func()) {
	t.Helper()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := reload(cfgs[i%len(cfgs)]); err != nil {
				t.Errorf("ReloadConfig: %v", err)
				return
			}
			time.Sleep(time.Millisecond) // still overlapping every reader, without flooding the log
		}
	}()
	work()
	close(stop)
	wg.Wait()
}
