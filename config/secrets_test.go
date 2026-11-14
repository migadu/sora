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
	if got[0] != masked || got[1] != "https://public.example.invalid/imap?mode=fixture" || got[2] != "backend.example.invalid:993" {
		t.Fatal("masking did not preserve public list values and redact URL userinfo")
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
