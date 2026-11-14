package config

import (
	"reflect"
	"testing"
)

func TestMaskSecretsURLUserInfoInLists(t *testing.T) {
	cfg := Config{DynamicServers: []ServerConfig{{RemoteAddrs: []string{
		"https://fixture-user:fixture-password@backend.example.invalid/imap",
		"https://public.example.invalid/imap?mode=fixture",
		"backend.example.invalid:993",
	}}}}
	MaskSecrets(&cfg)
	got := cfg.DynamicServers[0].RemoteAddrs
	const masked = "https://%2A%2A%2AMASKED%2A%2A%2A:%2A%2A%2AMASKED%2A%2A%2A@backend.example.invalid/imap"
	if got[0] != masked || got[1] != "https://public.example.invalid/imap?mode="+SecretMask || got[2] != "backend.example.invalid:993" {
		t.Fatal("masking did not redact URL credentials in list values or preserve the rest")
	}
}

func TestMaskSecretsMalformedURLUserInfo(t *testing.T) {
	for _, endpoint := range []string{
		"https://fixture-user:fixture-password@example.invalid/%zz",
		"https://fixture-user:fixture-password@example.invalid:bad/path",
	} {
		cfg := Config{Relay: RelayConfig{HTTPURL: endpoint}}
		MaskSecrets(&cfg)
		if cfg.Relay.HTTPURL != SecretMask {
			t.Fatal("unparseable URL exposed fixture credentials")
		}
	}
}

// Endpoint APIs authenticate with query parameters of any name, so a masked dump
// masks every query value and keeps the names, scheme, host, path and fragment (#596).
func TestMaskSecretsURLQueryValues(t *testing.T) {
	const m = SecretMask
	for _, tc := range []struct{ in, want string }{
		{"https://relay.example.invalid/send?api_key=fixture-query-secret",
			"https://relay.example.invalid/send?api_key=" + m},
		// Values are masked as written, percent-encoded or not; names are kept as written.
		{"https://relay.example.invalid/send?mode=fixture&api%5Fkey=fixture%2Dquery%2Dsecret&sig=fixture%3D%3D",
			"https://relay.example.invalid/send?mode=" + m + "&api%5Fkey=" + m + "&sig=" + m},
		// A component without "=" may be a token itself.
		{"https://hooks.example.invalid/notify?fixture-bare-token",
			"https://hooks.example.invalid/notify?" + m},
		// Only "&" separates parameters, so a ";" stays inside the masked value.
		{"https://relay.example.invalid/send?mode=fixture;token=fixture-query-secret",
			"https://relay.example.invalid/send?mode=" + m},
		// An empty value stays empty, as an unset secret does.
		{"https://relay.example.invalid/send?empty=&&token=fixture-query-secret",
			"https://relay.example.invalid/send?empty=&&token=" + m},
		// Remote lookup fills in $email and $ip per request: templates, not credentials.
		{"https://lookup.example.invalid/lookup?email=$email&ip=$ip&token=fixture-query-secret",
			"https://lookup.example.invalid/lookup?email=$email&ip=$ip&token=" + m},
		{"https://fixture-user:fixture-password@relay.example.invalid:8443/send%2Fmail?token=fixture-query-secret#fragment",
			"https://%2A%2A%2AMASKED%2A%2A%2A:%2A%2A%2AMASKED%2A%2A%2A@relay.example.invalid:8443/send%2Fmail?token=" + m + "#fragment"},
		// No query: a "?" in the fragment or escaped in the path, or an empty query.
		{"https://relay.example.invalid/send#fixture?token=fragment", "https://relay.example.invalid/send#fixture?token=fragment"},
		{"https://relay.example.invalid/send%3Ftoken=path", "https://relay.example.invalid/send%3Ftoken=path"},
		{"https://relay.example.invalid/send?", "https://relay.example.invalid/send?"},
		// A query in a URL that does not parse is not printed either.
		{"https://relay.example.invalid/%zz?api_key=fixture-query-secret", m},
		{"https://relay.example.invalid:bad/send?fixture-bare-token", m},
	} {
		cfg := Config{Relay: RelayConfig{HTTPURL: tc.in}}
		MaskSecrets(&cfg)
		if cfg.Relay.HTTPURL != tc.want {
			t.Errorf("MaskSecrets(%q) = %q, want %q", tc.in, cfg.Relay.HTTPURL, tc.want)
		}
	}
}

func TestMaskSecretsSubSchemePrefixedAndEmbeddedURLs(t *testing.T) {
	const (
		m      = SecretMask
		masked = "%2A%2A%2AMASKED%2A%2A%2A:%2A%2A%2AMASKED%2A%2A%2A"
	)
	for _, tc := range []struct{ in, want string }{
		// Sub-scheme / compound-scheme URLs (url.Parse treats outer scheme as opaque).
		{"jdbc:postgresql://fixture-user:fixture-password@db.internal:5432/mail",
			"jdbc:postgresql://" + masked + "@db.internal:5432/mail"},
		{"jdbc:postgresql://fixture-user:fixture-password@db.internal:5432/mail?sslmode=require&password=fixture-query-secret",
			"jdbc:postgresql://" + masked + "@db.internal:5432/mail?sslmode=" + m + "&password=" + m},
		// Leading slash or surrounding whitespace before scheme://.
		{"/https://fixture-user:fixture-password@backend.example.invalid/path",
			"/https://" + masked + "@backend.example.invalid/path"},
		{"  https://fixture-user:fixture-password@backend.example.invalid/path?token=fixture-query-secret  ",
			"  https://" + masked + "@backend.example.invalid/path?token=" + m + "  "},
		// Embedded URLs in path, fragment, and query, plus comma/space-separated URLs.
		{"https://proxy.example.invalid/fetch/https://fixture-user:fixture-password@backend.example.invalid/api",
			"https://proxy.example.invalid/fetch/https://" + masked + "@backend.example.invalid/api"},
		{"https://proxy.example.invalid/fetch#redirect=https://fixture-user:fixture-password@backend.example.invalid/api?token=fixture-query-secret",
			"https://proxy.example.invalid/fetch#redirect=https://" + masked + "@backend.example.invalid/api?token=" + m},
		{"https://proxy.example.invalid/fetch?target=https://fixture-user:fixture-password@backend.example.invalid/api&api_key=fixture-outer-secret",
			"https://proxy.example.invalid/fetch?target=" + m + "&api_key=" + m},
		{"https://public.example.invalid/a,https://fixture-user:fixture-password@backend.example.invalid/b?token=fixture-query-secret",
			"https://public.example.invalid/a,https://" + masked + "@backend.example.invalid/b?token=" + m},
		{"https://fixture-user:fixture-password@h1.example.invalid/a https://fixture-user2:fixture-password2@h2.example.invalid/b",
			"https://" + masked + "@h1.example.invalid/a https://" + masked + "@h2.example.invalid/b"},
		// Missing scheme or unencoded "://" inside userinfo fails closed.
		{"://fixture-user:fixture-password@backend.example.invalid/path", m},
		{"123://backend.example.invalid/path?token=fixture-query-secret", m},
		{"https://fixture-user:fixture-secret://123@backend.example.invalid/api", m},
	} {
		cfg := Config{Relay: RelayConfig{HTTPURL: tc.in}}
		MaskSecrets(&cfg)
		if cfg.Relay.HTTPURL != tc.want {
			t.Errorf("MaskSecrets(%q) = %q, want %q", tc.in, cfg.Relay.HTTPURL, tc.want)
		}
	}
}

func TestMaskSecretsInterfaceFields(t *testing.T) {
	const masked = "%2A%2A%2AMASKED%2A%2A%2A:%2A%2A%2AMASKED%2A%2A%2A"
	cfg := Config{
		Database: DatabaseConfig{
			Write: &DatabaseEndpointConfig{
				Port: "jdbc:postgresql://fixture-user:fixture-password@db.internal:5432/mail",
			},
			Read: &DatabaseEndpointConfig{
				Port: 5432,
			},
		},
		DynamicServers: []ServerConfig{{
			RemotePort: "https://fixture-user:fixture-password@backend.example.invalid:993",
			RemoteLookup: &RemoteLookupConfig{
				RemotePort: "https://lookup.example.invalid/lookup?token=fixture-query-secret",
			},
		}},
	}
	MaskSecrets(&cfg)

	if got, want := cfg.Database.Write.Port, "jdbc:postgresql://"+masked+"@db.internal:5432/mail"; got != want {
		t.Errorf("Database.Write.Port = %v, want %q", got, want)
	}
	if got := cfg.Database.Read.Port; got != 5432 {
		t.Errorf("Database.Read.Port = %v, want 5432", got)
	}
	if got, want := cfg.DynamicServers[0].RemotePort, "https://"+masked+"@backend.example.invalid:993"; got != want {
		t.Errorf("DynamicServers[0].RemotePort = %v, want %q", got, want)
	}
	if got, want := cfg.DynamicServers[0].RemoteLookup.RemotePort, "https://lookup.example.invalid/lookup?token="+SecretMask; got != want {
		t.Errorf("RemoteLookup.RemotePort = %v, want %q", got, want)
	}

	type secretAnyProbe struct {
		SecretVal   any `secret:"true"`
		EmptyVal    any `secret:"true"`
		SecretSlice any `secret:"true"`
		PublicMap   any
	}
	probe := secretAnyProbe{
		SecretVal:   "fixture-secret-value",
		EmptyVal:    "",
		SecretSlice: []any{"fixture-slice-secret", ""},
		PublicMap:   map[string]any{"dsn": "https://fixture-user:fixture-password@db.example.invalid/mail"},
	}
	maskSecrets(reflect.ValueOf(&probe).Elem(), false)
	if probe.SecretVal != SecretMask {
		t.Errorf("SecretVal = %v, want %q", probe.SecretVal, SecretMask)
	}
	if probe.EmptyVal != "" {
		t.Errorf("EmptyVal = %v, want empty string", probe.EmptyVal)
	}
	if got := probe.SecretSlice.([]any); got[0] != SecretMask || got[1] != "" {
		t.Errorf("SecretSlice = %#v, want [%q, \"\"]", got, SecretMask)
	}
	if got, want := probe.PublicMap.(map[string]any)["dsn"], "https://"+masked+"@db.example.invalid/mail"; got != want {
		t.Errorf("PublicMap[dsn] = %v, want %q", got, want)
	}
}
