package userapiproxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/userapi"
)

func TestPools_UnownedPinMustFailClosed(t *testing.T) {
	for _, mode := range []string{"maintenance", "restrict_to_pool", "cached_maintenance", "cached_restrict_to_pool"} {
		t.Run(mode, func(t *testing.T) {
			s, maintenance := newPoolsMaintenanceServer(t)
			s.routingLookup = &scriptedLookup{info: &proxy.UserRoutingInfo{ServerAddress: "10.9.9.9:8081"}, result: proxy.AuthSuccess}
			if strings.HasSuffix(mode, "maintenance") {
				maintenance.Set([]string{"10.9.9.9"})
			} else {
				s.connManager.SetRestrictRemoteLookupToPool(true)
			}
			if strings.HasPrefix(mode, "cached_") {
				s.lookupCache = lookupcache.New("test", "test", time.Minute, time.Minute, 10, time.Hour, 0)
				t.Cleanup(func() { _ = s.lookupCache.Stop(context.Background()) })
				s.lookupCache.Set(s.name, "user@external-pool.example", &lookupcache.CacheEntry{ServerAddress: "10.9.9.9:8081"})
				s.routingLookup = nil
			}
			got, err := s.getBackendForUser(context.Background(), "user@external-pool.example", 42)
			if err == nil {
				t.Fatalf("pin to external pool silently routed account 42 to %+v", got)
			}
		})
	}
}

func TestPools_RemovedRemoteUserMustNotBecomeLocal(t *testing.T) {
	s, _ := newPoolsMaintenanceServer(t)
	s.lookupLocalUsers = true
	s.routingLookup = &scriptedLookup{result: proxy.AuthUserNotFound}
	s.lookupCache = lookupcache.New("test", "test", time.Minute, time.Minute, 10, time.Hour, 0)
	t.Cleanup(func() { _ = s.lookupCache.Stop(context.Background()) })
	// The user presents a still-valid JWT issued in another pool before its lookup
	// entry was removed. Local fallback needs to establish ownership of account 42.
	for i := 0; i < 2; i++ {
		got, err := s.getBackendForUser(context.Background(), "removed@remote.example", 42)
		if err == nil {
			t.Fatalf("404 sent the remote JWT's account 42 to %+v without any local identity check", got)
		}
	}
}

func TestPools_AuthUsesEndpointJSONSchema(t *testing.T) {
	const email, secret = "user@pool-b.example", "test-secret-key-at-least-32-bytes!!"
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{Email: email, AccountID: 42,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, path, body string }{
		{"login numeric token", "login", `{"email":"` + email + `","password":"secret","token":123}`},
		{"login object token", "login", `{"token":{"email":"other@example.com"},"email":"` + email + `","password":"secret"}`},
		{"refresh numeric email", "refresh", `{"token":"` + token + `","email":123}`},
		{"refresh object email", "refresh", `{"email":{"token":"other"},"token":"` + token + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var backendRequest any = &userapi.LoginRequest{}
			if tc.path == "refresh" {
				backendRequest = &userapi.RefreshTokenRequest{}
			}
			if err := json.NewDecoder(strings.NewReader(tc.body)).Decode(backendRequest); err != nil {
				t.Fatal(err)
			}
			s, _ := newPoolsMaintenanceServer(t)
			s.settings.Store(&reloadableSettings{jwtSecret: secret})
			lookup := poolAnswer("sora1")
			s.routingLookup = lookup
			req := httptest.NewRequest("POST", "/user/auth/"+tc.path, strings.NewReader(tc.body))
			route, err := s.routeAuthRequest(req)
			if err != nil || !strings.HasPrefix(route.addr, "10.0.1.") {
				t.Fatalf("valid backend auth request routed to %+v, err=%v; lookup asked %v", route, err, lookup.asked())
			}
			if asked := lookup.asked(); len(asked) != 1 || asked[0] != email {
				t.Fatalf("looked up %v, want %s", asked, email)
			}
			forwarded, err := io.ReadAll(req.Body)
			if err != nil || string(forwarded) != tc.body {
				t.Fatalf("auth body changed: %q, %v", forwarded, err)
			}
		})
	}
}

func TestPools_InvalidLookupCannotEnableLocalFallback(t *testing.T) {
	s, err := New(context.Background(), nil, ServerOptions{
		Name: "test", JWTSecret: "test-secret-key-at-least-32-bytes!!",
		Pools:        []proxy.PoolSpec{{Name: "default", Default: true, Backends: []string{"127.0.0.1:8081"}}},
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, LookupLocalUsers: true, URL: "http://lookup.example.com"},
	})
	if err == nil {
		s.cancel()
		t.Fatal("invalid lookup started a named-pool proxy with local fallback")
	}
}
