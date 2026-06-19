//go:build integration

package managesieveproxy_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieveproxy"
	"golang.org/x/crypto/bcrypt"
)

// TestManageSieveProxy_MasterTokenViaRemoteLookup reproduces the production path:
// a master token (which contains '@') is submitted as user@domain@<master@token> and the
// ManageSieve proxy resolves it via a remote-lookup API (not local DB).
//
// Two remote-lookup behaviours are covered:
//   - "WithAddress": the API returns the resolved address (ActualEmail). The proxy should
//     impersonate that clean address on the backend.
//   - "WithoutAddress": the API authenticates but does NOT echo back a resolved address.
//     The proxy then forwards the submitted identity (which still carries the @-token suffix)
//     to the backend. IMAP/POP3 backends strip the suffix (BaseAddress) before resolving the
//     account; the ManageSieve backend must do the same.
func TestManageSieveProxy_MasterTokenViaRemoteLookup(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// A master token containing '@', submitted as the address suffix.
	const masterToken = "admin@master.example.com"
	const masterPassword = "proxy_master_123"

	backendServer, account := common.SetupManageSieveServerWithPROXY(t)
	defer backendServer.Close()

	// The remote API "validates the token" by returning a hash of the password the user typed.
	passwordHashBytes, err := bcrypt.GenerateFromPassword([]byte(masterPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	passwordHash := string(passwordHashBytes)

	// addressToReturn is the value the mock remote-lookup puts in the "address" field
	// ("" means omit it entirely). expectOK is the expected client-→proxy auth outcome.
	run := func(t *testing.T, addressToReturn string, expectOK bool) {
		var calls atomic.Int32
		lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			t.Logf("RemoteLookup call: %s", r.URL.Path)
			resp := map[string]interface{}{
				"password_hash": passwordHash,
				"server":        backendServer.Address,
			}
			if addressToReturn != "" {
				resp["address"] = addressToReturn
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(resp)
		}))
		defer lookup.Close()

		proxyAddress := common.GetRandomAddress(t)
		proxy := setupManageSieveProxyWithRemoteLookupNoMaster(t, backendServer.ResilientDB, proxyAddress,
			[]string{backendServer.Address}, lookup.URL)
		defer proxy.Close()

		client, err := NewManageSieveClient(proxyAddress)
		if err != nil {
			t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
		}
		defer client.Close()

		// Submitted form: user@domain.com@admin@master.example.com  (token has an '@')
		username := account.Email + "@" + masterToken
		authString := "\x00" + username + "\x00" + masterPassword
		encoded := base64.StdEncoding.EncodeToString([]byte(authString))

		if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded)); err != nil {
			t.Fatalf("AUTHENTICATE command failed: %v", err)
		}
		response, err := client.ReadResponse()
		if err != nil {
			t.Fatalf("Failed to read AUTHENTICATE response: %v", err)
		}
		gotOK := strings.HasPrefix(response, "OK")
		if gotOK != expectOK {
			t.Fatalf("addressReturned=%q: expected OK=%v, got %q", addressToReturn, expectOK, response)
		}
		if !expectOK {
			// Documents the user-reported failure: a remote-lookup response that omits
			// the resolved address is rejected as an invalid response and surfaces as
			// `NO "Authentication failed"` — identically for IMAP/POP3/ManageSieve.
			t.Logf("✓ Correctly rejected (no resolved address): %s", response)
			return
		}
		t.Logf("✓ Authenticated (addressReturned=%q)", addressToReturn)

		// Must bind to the impersonated account and list its scripts.
		if err := client.SendCommand("LISTSCRIPTS"); err != nil {
			t.Fatalf("LISTSCRIPTS command failed: %v", err)
		}
		for {
			response, err := client.ReadResponse()
			if err != nil {
				t.Fatalf("Failed to read LISTSCRIPTS response: %v", err)
			}
			if response == "OK" {
				break
			}
		}
		t.Logf("✓ LISTSCRIPTS successful (addressReturned=%q)", addressToReturn)
	}

	// Happy path: remote lookup resolves the @-token to a clean address → master access works.
	t.Run("RemoteLookup returns clean resolved address", func(t *testing.T) {
		run(t, account.Email, true)
	})
	// Faithful production case: the SAME endpoint is used for IMAP and ManageSieve and echoes
	// back an address that still carries the @-token suffix. IMAP strips it (BaseAddress) and
	// works; the ManageSieve backend must do the same. Before the fix this returned
	// `NO "Impersonation target user not found"` because the backend looked up FullAddress()
	// (which still contained the @master token).
	t.Run("RemoteLookup echoes address carrying the @-token suffix", func(t *testing.T) {
		run(t, account.Email+"@"+masterToken, true)
	})
	// Remote lookup authenticates but omits the resolved address entirely: rejected by the
	// shared remote-lookup contract (address is required), surfaces as `NO "Authentication failed"`.
	t.Run("RemoteLookup omits resolved address", func(t *testing.T) { run(t, "", false) })
}

// setupManageSieveProxyWithRemoteLookupNoMaster sets up a ManageSieve proxy that has NO local
// master username configured (so the @-suffix is treated as a remote-lookup token) but does have
// master SASL for proxy→backend impersonation.
func setupManageSieveProxyWithRemoteLookupNoMaster(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, lookupURL string) *common.TestServer {
	t.Helper()

	opts := managesieveproxy.ServerOptions{
		Name:                   "test-managesieve-proxy-master-remotelookup",
		Addr:                   proxyAddr,
		RemoteAddrs:            backendAddrs,
		RemotePort:             4190,
		InsecureAuth:           true,
		MasterSASLUsername:     "master_sasl",
		MasterSASLPassword:     "master_sasl_secret",
		TLS:                    false,
		RemoteTLS:              false,
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit:          server.AuthRateLimiterConfig{Enabled: false},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:                true,
			URL:                    lookupURL + "/$email",
			Timeout:                "5s",
			RemoteUseProxyProtocol: true,
		},
	}

	proxy, err := managesieveproxy.New(context.Background(), rdb, "test-host", opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("ManageSieve proxy error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}
