package config

import "testing"

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
