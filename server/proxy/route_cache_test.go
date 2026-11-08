package proxy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/migadu/sora/pkg/lookupcache"
)

// A lookup answer survives the lookup cache whole: a login served from the cache routes
// exactly as the uncached login it was cached from, with every backend-leg setting the
// answer carried and the pin still enforced. Every Remote* setting UserRoutingInfo has
// must round-trip, so a setting added later cannot be silently dropped on cache hits.
func TestRoutingInfoSurvivesTheLookupCache(t *testing.T) {
	pin := &UserRoutingInfo{ServerAddress: "10.0.0.9:110", AccountID: 7, IsRemoteLookupAccount: true}
	v := reflect.ValueOf(pin).Elem()
	var settings []string
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if strings.HasPrefix(f.Name, "Remote") && f.Type.Kind() == reflect.Bool {
			v.Field(i).SetBool(true)
			settings = append(settings, f.Name)
		}
	}
	if len(settings) < 7 {
		t.Fatalf("setup: found only %v", settings)
	}

	entry := &lookupcache.CacheEntry{}
	CacheRoute(entry, pin)
	if !entry.FromRemoteLookup {
		t.Fatal("a remote-lookup answer is not marked as one in the cache")
	}
	got := RouteFromCache(entry)
	gv := reflect.ValueOf(got).Elem()
	for _, name := range settings {
		if !gv.FieldByName(name).Bool() {
			t.Errorf("%s was lost on the way through the lookup cache", name)
		}
	}
	if got.ServerAddress != pin.ServerAddress || got.AccountID != 7 || !got.IsRemoteLookupAccount || got.AuthOnlyMode {
		t.Errorf("pin came back as %+v", got)
	}

	// A pool answer and an auth-only answer keep their meaning too.
	pooled := RouteFromCache(func() *lookupcache.CacheEntry {
		e := &lookupcache.CacheEntry{}
		CacheRoute(e, &UserRoutingInfo{PoolName: "sora1", IsRemoteLookupAccount: true, AuthOnlyMode: true})
		return e
	}())
	if pooled.PoolName != "sora1" || pooled.ServerAddress != "" || !pooled.IsRemoteLookupAccount || !pooled.AuthOnlyMode {
		t.Errorf("pool answer came back as %+v", pooled)
	}

	// A user found in the proxy's own database was not answered by the lookup.
	local := RouteFromCache(&lookupcache.CacheEntry{AccountID: 3})
	if local.IsRemoteLookupAccount || local.AuthOnlyMode || local.ServerAddress != "" {
		t.Errorf("database user came back as %+v", local)
	}
}
