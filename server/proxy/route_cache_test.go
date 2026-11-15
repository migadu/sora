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

// TestMasterFormOtherCredential (#949): under the master username form a cached positive
// entry and the password now presented are revalidated, not refused, exactly when one of
// them is the master password and the other is not. Any other pair, and any other name,
// keeps the fresh-entry refusal of a different password.
func TestMasterFormOtherCredential(t *testing.T) {
	master, masterPassword := []byte("admin"), []byte("master-secret")

	tests := []struct {
		name, username, presented, cached string
		want                              bool
	}{
		{"master password after the account's own login", "user@example.com@admin", "master-secret", "own-password", true},
		{"account's own password after a master login", "user@example.com@admin", "own-password", "master-secret", true},
		{"wrong password after the account's own login", "user@example.com@admin", "wrong-password", "own-password", false},
		{"wrong password after a master login", "user@example.com@admin", "wrong-password", "master-secret", true},
		{"master password under another suffix", "user@example.com@TOKEN", "master-secret", "own-password", false},
		{"master password without a suffix", "user@example.com", "master-secret", "own-password", false},
		{"suffix differs in case", "user@example.com@Admin", "master-secret", "own-password", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MasterFormOtherCredential(tt.username, tt.presented, lookupcache.NewPasswordDigest(tt.cached), master, masterPassword)
			if got != tt.want {
				t.Errorf("MasterFormOtherCredential(%q, %q, digest of %q) = %v, want %v", tt.username, tt.presented, tt.cached, got, tt.want)
			}
		})
	}

	// Without master credentials nothing is the master form.
	if MasterFormOtherCredential("user@example.com@admin", "master-secret", lookupcache.NewPasswordDigest("own-password"), master, nil) {
		t.Error("MasterFormOtherCredential with no master password = true, want false")
	}
	if MasterFormOtherCredential("user@example.com@admin", "master-secret", lookupcache.NewPasswordDigest("own-password"), nil, masterPassword) {
		t.Error("MasterFormOtherCredential with no master username = true, want false")
	}
}
