package proxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// TestRemoteLookupHidesURLCredentials: the lookup URL may carry the service's
// credentials in its userinfo or query. It is logged at start-up and per request,
// when the breaker refuses a lookup, and net/http quotes it in the errors the proxies
// log, with the user name and the query (#806).
func TestRemoteLookupHidesURLCredentials(t *testing.T) {
	logs := &syncBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { logger.Swap(prev) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddr := ln.Addr().String()
	ln.Close()

	ctx := context.Background()
	var errs []error
	lookup, err := InitializeRemoteLookup("imap", &config.RemoteLookupConfig{
		Enabled: true,
		URL:     "http://fixture-user:fixture-password@" + closedAddr + "/lookup?email=$email&api_key=fixture-query-secret",
	}, 0)
	if err != nil {
		t.Fatalf("InitializeRemoteLookup: %v", err)
	}
	client := lookup.(*HTTPRemoteLookupClient)
	// The default breaker opens after three failed lookups; the fourth is refused.
	for range 4 {
		_, _, err := client.LookupUserRoute(ctx, "user@example.com", "password")
		errs = append(errs, err)
	}
	errs = append(errs, client.HealthCheck(ctx))

	// Client.Do parses Location before the no-redirect hook is called. The
	// malformed URL and the partial password in its reason must both stay hidden.
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://fixture-user:fixture/password@lookup.example.invalid/lookup?api_key=fixture-query-secret")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer redirect.Close()
	lookup, err = InitializeRemoteLookup("imap", &config.RemoteLookupConfig{
		Enabled: true,
		URL:     redirect.URL + "/lookup?email=$email",
	}, 0)
	if err != nil {
		t.Fatalf("InitializeRemoteLookup redirect fixture: %v", err)
	}
	redirectClient := lookup.(*HTTPRemoteLookupClient)
	_, _, err = redirectClient.LookupUserRoute(ctx, "user@example.com", "password")
	errs = append(errs, err, redirectClient.HealthCheck(ctx))

	// A URL that does not parse is quoted whole, its reason a piece of it.
	_, err = InitializeRemoteLookup("imap", &config.RemoteLookupConfig{
		Enabled: true,
		URL:     "https://fixture-user:fixture/password@lookup.example.invalid/lookup/$email",
	}, 0)
	if err == nil {
		t.Fatal("InitializeRemoteLookup accepted an unparsable URL")
	}
	errs = append(errs, err)

	for _, err := range errs {
		if err == nil {
			t.Fatal("a lookup against a closed port succeeded")
		}
		if strings.Contains(err.Error(), "fixture") {
			t.Errorf("error quotes the lookup's credentials: %v", err)
		}
	}
	logged := logs.String()
	for _, want := range []string{"Initializing HTTP remotelookup", "Requesting lookup", "Circuit breaker is open"} {
		if !strings.Contains(logged, want) {
			t.Errorf("no %q record logged", want)
		}
	}
	if strings.Contains(logged, "fixture") {
		t.Errorf("log quotes the lookup's credentials:\n%s", logged)
	}
}
