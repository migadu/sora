package config

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// lookupTableKeysReadBy is every key of the [server.remote_lookup] and
// [server.lookup_cache] tables, as a line that sets it, with the server types that read
// it (#1418). The line goes through the TOML decoder: a lookup_cache table is decoded on
// top of the defaults, so only the decoder knows which keys the table names.
var lookupTableKeysReadBy = func() map[string]map[string]struct {
	line  string
	types []string
} {
	lineProxies := []string{"imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy"}
	proxies := append(slices.Clone(lineProxies), "user_api_proxy")
	cacheReaders := []string{"imap", "pop3", "managesieve", "imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy", "user_api_proxy"}
	type key = struct {
		line  string
		types []string
	}
	return map[string]map[string]key{
		// InitializeRemoteLookup builds every proxy's lookup client from the table. The
		// client stamps the backend-leg keys on the route of a backend the lookup names;
		// each line proxy's session reads those of its protocol, and the User API proxy
		// dials such a backend with the [[server]] block's own settings (serverRoute).
		"remote_lookup": {
			"enabled":                   {`enabled = true`, proxies},
			"url":                       {`url = "https://lookup.example.com/$email"`, proxies},
			"timeout":                   {`timeout = "3s"`, proxies},
			"auth_token":                {`auth_token = "example-token"`, proxies},
			"lookup_local_users":        {`lookup_local_users = true`, proxies},
			"user_not_found_response":   {`user_not_found_response = "tempfail"`, []string{"lmtp_proxy"}},
			"remote_tls":                {`remote_tls = true`, lineProxies},
			"remote_tls_use_starttls":   {"remote_tls = true\nremote_tls_use_starttls = true", lineProxies},
			"remote_tls_verify":         {`remote_tls_verify = false`, lineProxies},
			"remote_port":               {`remote_port = 1143`, proxies},
			"remote_use_proxy_protocol": {`remote_use_proxy_protocol = true`, lineProxies},
			"remote_use_id_command":     {`remote_use_id_command = true`, []string{"imap_proxy"}},
			"remote_use_xclient":        {`remote_use_xclient = true`, []string{"pop3_proxy", "lmtp_proxy"}},
			"remote_use_utf8":           {`remote_use_utf8 = true`, []string{"pop3_proxy"}},
			"restrict_to_pool":          {`restrict_to_pool = true`, proxies},
			"circuit_breaker":           {`circuit_breaker = { max_requests = 5 }`, proxies},
			"transport":                 {`transport = { max_idle_conns = 10 }`, proxies},
		},
		// LMTP and User API proxies cache routes without checking passwords.
		"lookup_cache": {
			"enabled":                      {`enabled = false`, cacheReaders},
			"positive_ttl":                 {`positive_ttl = "10m"`, cacheReaders},
			"negative_ttl":                 {`negative_ttl = "2m"`, cacheReaders},
			"max_size":                     {`max_size = 1000`, cacheReaders},
			"cleanup_interval":             {`cleanup_interval = "10m"`, cacheReaders},
			"positive_revalidation_window": {`positive_revalidation_window = "1m"`, slices.DeleteFunc(slices.Clone(cacheReaders), func(t string) bool { return t == "lmtp_proxy" || t == "user_api_proxy" })},
		},
	}
}()

// TestLookupTableKeysReadByCoversEveryKey keeps lookupTableKeysReadBy complete: a new
// remote_lookup or lookup_cache key needs a decision on which server types read it.
func TestLookupTableKeysReadByCoversEveryKey(t *testing.T) {
	for table, typ := range map[string]reflect.Type{
		"remote_lookup": reflect.TypeOf(RemoteLookupConfig{}),
		"lookup_cache":  reflect.TypeOf(LookupCacheConfig{}),
	} {
		keys := map[string]bool{}
		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			key := tomlKey(field)
			keys[key] = true
			if _, ok := lookupTableKeysReadBy[table][key]; !ok {
				t.Errorf("%s.%s is not in lookupTableKeysReadBy: say which server types read it", table, key)
			}
		}
		for key := range lookupTableKeysReadBy[table] {
			if !keys[key] {
				t.Errorf("lookupTableKeysReadBy lists %s.%s, which the table does not have", table, key)
			}
		}
	}
}

// Each remote_lookup and lookup_cache key set on a server type that reads the table but
// not the key is reported at startup, naming the key and the server (#1418); on a type
// that reads the key, nothing names it. A type that does not read the table is told
// about the table as a whole, and only about the table.
func TestWarnUnusedConfigOptions_LookupTableKeysTheServerTypeDoesNotRead(t *testing.T) {
	for table, keys := range lookupTableKeysReadBy {
		for key, spec := range keys {
			for _, serverType := range ServerTypes {
				t.Run(table+"."+key+"/"+serverType, func(t *testing.T) {
					var s ServerConfig
					src := fmt.Sprintf("type = %q\nname = \"server-1418\"\n[%s]\n%s\n", serverType, table, spec.line)
					if _, err := toml.Decode(src, &s); err != nil {
						t.Fatalf("decode %q: %v", src, err)
					}
					var named, tableNamed []string
					for _, w := range warningsFor(s) {
						if strings.Contains(w, "'"+table+"."+key+"'") {
							named = append(named, w)
						}
						if strings.Contains(w, "'"+table+"'") {
							tableNamed = append(tableNamed, w)
						}
					}
					readsTable := slices.Contains(lookupTableKeysReadBy[table]["enabled"].types, serverType)
					switch {
					case !readsTable:
						if len(named) > 0 || len(tableNamed) != 1 {
							t.Errorf("%s does not read [%s]: want one warning naming the table and none naming %s.%s, got %v", serverType, table, table, key, warningsFor(s))
						}
					case slices.Contains(spec.types, serverType):
						if len(named) > 0 {
							t.Errorf("%s reads %s.%s but it was warned about: %v", serverType, table, key, named)
						}
					default:
						if len(named) != 1 || !strings.Contains(named[0], "server-1418") {
							t.Errorf("%s.%s on %s (read by %v only): want one warning naming it on server-1418, got %v", table, key, serverType, spec.types, named)
						}
					}
				})
			}
		}
	}
}

// The User API proxy dials a backend a lookup names with the [[server]] block's own
// settings, so the warning about a remote_lookup.remote_tls_use_starttls it ignores
// names the block's remote_tls, the key that selects HTTPS there, and not
// remote_lookup.remote_tls, which it ignores too (#1418).
func TestWarnUnusedConfigOptions_UserAPIProxyLookupStartTLSNamesBlockRemoteTLS(t *testing.T) {
	s := ServerConfig{Type: "user_api_proxy", Name: "server-1418", RemoteLookup: &RemoteLookupConfig{RemoteTLSUseStartTLS: true}}
	var named []string
	for _, w := range warningsFor(s) {
		if strings.Contains(w, "'remote_lookup.remote_tls_use_starttls'") {
			named = append(named, w)
		}
	}
	if len(named) != 1 || !strings.Contains(named[0], "'remote_tls'") || strings.Contains(named[0], "'remote_lookup.remote_tls'") {
		t.Errorf("want one warning naming the block's 'remote_tls' and not 'remote_lookup.remote_tls', got %v", named)
	}
}
