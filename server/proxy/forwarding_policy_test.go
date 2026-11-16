package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/stretchr/testify/require"
)

func TestForwardingPolicyLookupPoolAndCachePropagation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"address":"user@example.com","server":"127.0.0.1:143"}`)
	}))
	defer s.Close()
	for _, skip := range []bool{false, true} {
		t.Run(fmt.Sprintf("skip_%t", skip), func(t *testing.T) {
			client, err := InitializeRemoteLookup("imap", &config.RemoteLookupConfig{Enabled: true, URL: s.URL,
				RemoteUseProxyProtocol: true, RemoteUseIDCommand: true, RemoteSkipForwardingWithProxyProtocol: skip}, 0)
			require.NoError(t, err)
			defer client.Close()
			pin, result, err := client.LookupUserRouteWithOptions(context.Background(), "user@example.com", "", true)
			require.NoError(t, err)
			require.Equal(t, AuthSuccess, result)
			require.Equal(t, skip, pin.RemoteSkipForwardingWithProxyProtocol, "lookup config must reach its pin")
			e := &lookupcache.CacheEntry{RemoteSkipForwardingWithProxyProtocol: !skip}
			CacheRoute(e, pin)
			require.Equal(t, skip, RouteFromCache(e).RemoteSkipForwardingWithProxyProtocol, "cache must copyfalse too, replacing an oldertrue policy")
			specs := PoolSpecsFromConfig([]config.PoolConfig{{Name: "p", Backends: []string{"127.0.0.1:143"}, Default: true,
				RemoteUseProxyProtocol: true, RemoteUseIDCommand: true, RemoteSkipForwardingWithProxyProtocol: skip}})
			require.Equal(t, skip, specs[0].Settings.SkipForwardingWithProxyProtocol)
			cm := newPoolsCM(t, specs)
			route := &UserRoutingInfo{PoolName: "p", IsRemoteLookupAccount: true, RemoteSkipForwardingWithProxyProtocol: !skip}
			selected, err := routeFor(t, cm, route, nil)
			require.NoError(t, err)
			require.Equal(t, skip, selected.RoutingInfo.RemoteSkipForwardingWithProxyProtocol, "pool must replace lookup's opposite policy")
			CacheRoute(e, selected.RoutingInfo)
			require.Equal(t, skip, RouteFromCache(e).RemoteSkipForwardingWithProxyProtocol)
		})
	}
}
