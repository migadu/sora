//go:build integration

package userapiproxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/userapi"
	"github.com/migadu/sora/server/userapiproxy"
)

func TestPools_RemoteTokenMustNotReadLocalAccount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	victim := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("review-victim-%d@example.com", time.Now().UnixNano()), "victim-password")
	accountID, err := rdb.GetActiveAccountIDByAddressWithRetry(context.Background(), victim.Email)
	if err != nil {
		t.Fatal(err)
	}
	const marker = "Private-Victim-Mailbox"
	if err := rdb.CreateMailboxForUserWithRetry(context.Background(), accountID, marker); err != nil {
		t.Fatal(err)
	}
	backend := newCountingBackend(t, rdb, "local-default")
	// Represents a still-valid token issued in another database/pool whose local
	// account ID happens to equal the victim's ID. All pools share the signing key.
	claims := userapi.JWTClaims{Email: "removed@remote-pool.example", AccountID: accountID,
		RegisteredClaims: jwt.RegisteredClaims{Issuer: "test-issuer", Subject: "removed@remote-pool.example", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"lookup_404", "pin_in_maintenance", "refused_pin"} {
		t.Run(mode, func(t *testing.T) {
			lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "lookup_404" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				fmt.Fprint(w, `{"address":"removed@remote-pool.example","server":"127.0.0.9:8081"}`)
			}))
			defer lookup.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			addr := common.GetRandomAddress(t)
			p, err := userapiproxy.New(ctx, rdb, userapiproxy.ServerOptions{Name: "review", Addr: addr, JWTSecret: testJWTSecret,
				Pools:        []proxy.PoolSpec{{Name: "local", Default: true, Backends: []string{backend.addr()}}, {Name: "remote", Backends: []string{"127.0.0.2:8081"}}},
				LookupCache:  &config.LookupCacheConfig{Enabled: true, PositiveTTL: "1m", NegativeTTL: "1m"},
				RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "2s", LookupLocalUsers: true, RestrictToPool: mode == "refused_pin"}})
			if err != nil {
				t.Fatal(err)
			}
			m := proxy.NewMaintenance()
			if mode == "pin_in_maintenance" {
				m.Set([]string{"127.0.0.9"})
			} else {
				m.Set(nil)
			}
			p.GetConnectionManager().SetMaintenance(m)
			go p.Start()
			time.Sleep(100 * time.Millisecond)
			request := func(token string) (int, string) {
				t.Helper()
				req, _ := http.NewRequest("GET", "http://"+addr+"/user/mailboxes", nil)
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				return resp.StatusCode, string(body)
			}
			if mode == "lookup_404" {
				// Local fallback still works, but neither a cached miss nor a real
				// local email authorizes a different account ID from a JWT.
				localClaims := claims
				localClaims.Email = victim.Email
				for _, id := range []int64{accountID, accountID + 1, accountID} {
					localClaims.AccountID = id
					localToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, localClaims).SignedString([]byte(testJWTSecret))
					if err != nil {
						t.Fatal(err)
					}
					status, body := request(localToken)
					want := http.StatusOK
					if id != accountID {
						want = http.StatusServiceUnavailable
					}
					if status != want || (status == http.StatusOK && !strings.Contains(body, marker)) {
						t.Fatalf("local fallback ID %d: status=%d, want %d", id, status, want)
					}
				}
			}
			for i := 0; i < 2; i++ {
				before := backend.count.Load()
				status, body := request(token)
				if status != http.StatusServiceUnavailable || strings.Contains(body, marker) || backend.count.Load() != before {
					t.Fatalf("request %d: remote token reached local account: status=%d, backend hits=%d", i, status, backend.count.Load()-before)
				}
			}
		})
	}
}

func TestPools_AuthExtraFieldsReachTheUsersPool(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("auth-schema-%d@example.com", time.Now().UnixNano()), "secret")
	for _, useDefault := range []bool{true, false} {
		t.Run(fmt.Sprintf("default=%v", useDefault), func(t *testing.T) {
			a, b := newCountingBackend(t, rdb, "a"), newCountingBackend(t, rdb, "b")
			lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]string{"address": account.Email, "pool": "b"})
			}))
			defer lookup.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			addr := common.GetRandomAddress(t)
			p, err := userapiproxy.New(ctx, rdb, userapiproxy.ServerOptions{
				Name: "schema", Addr: addr, JWTSecret: testJWTSecret,
				Pools:        []proxy.PoolSpec{{Name: "a", Default: useDefault, Backends: []string{a.addr()}}, {Name: "b", Backends: []string{b.addr()}}},
				RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "2s"},
			})
			if err != nil {
				t.Fatal(err)
			}
			go p.Start()
			time.Sleep(100 * time.Millisecond)
			post := func(path, body string) string {
				t.Helper()
				resp, err := http.Post("http://"+addr+path, "application/json", strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				raw, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("%s: status %d, %s", path, resp.StatusCode, raw)
				}
				var data userapi.LoginResponse
				if err := json.Unmarshal(raw, &data); err != nil || data.Token == "" {
					t.Fatalf("invalid auth response: %s, %v", raw, err)
				}
				return data.Token
			}
			token := post("/user/auth/login", fmt.Sprintf(`{"email":%q,"password":"secret","token":123}`, account.Email))
			post("/user/auth/refresh", fmt.Sprintf(`{"token":%q,"email":123}`, token))
			if a.count.Load() != 0 || b.count.Load() != 2 {
				t.Fatalf("auth routed to a=%d, b=%d; want a=0, b=2", a.count.Load(), b.count.Load())
			}
		})
	}
}
