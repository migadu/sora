package server

import (
	"crypto/tls"
	"slices"
	"strings"
	"testing"
)

// ListenerTLS.Config is the one rule every listener type resolves its
// certificate source and tls_verify by (#416). integration_tests/tls checks
// each listener type serves what it returns.
func TestListenerTLSConfig(t *testing.T) {
	const certFile, keyFile = "../testdata/sora.crt", "../testdata/sora.key"
	files, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	global := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{[]byte("global")}}},
		NextProtos:   []string{"imap", "pop3"},
	}

	cases := []struct {
		name       string
		l          ListenerTLS
		wantErr    string
		wantCert   []byte // first DER block of the served certificate
		wantALPN   []string
		wantClient tls.ClientAuthType
	}{
		{name: "global", l: ListenerTLS{Global: global},
			wantCert: []byte("global"), wantALPN: global.NextProtos, wantClient: tls.NoClientCert},
		{name: "global, tls_verify", l: ListenerTLS{Global: global, Verify: true},
			wantCert: []byte("global"), wantALPN: global.NextProtos, wantClient: tls.RequireAndVerifyClientCert},
		{name: "files", l: ListenerTLS{CertFile: certFile, KeyFile: keyFile, ALPN: []string{"lmtp"}},
			wantCert: files.Certificate[0], wantALPN: []string{"lmtp"}, wantClient: tls.NoClientCert},
		{name: "files, tls_verify", l: ListenerTLS{CertFile: certFile, KeyFile: keyFile, Verify: true},
			wantCert: files.Certificate[0], wantClient: tls.RequireAndVerifyClientCert},
		{name: "global wins over files", l: ListenerTLS{Global: global, CertFile: certFile, KeyFile: keyFile, ALPN: []string{"lmtp"}},
			wantCert: []byte("global"), wantALPN: global.NextProtos, wantClient: tls.NoClientCert},
		{name: "ignored files are not read", l: ListenerTLS{Global: global, CertFile: "/nonexistent.crt", Verify: true},
			wantCert: []byte("global"), wantALPN: global.NextProtos, wantClient: tls.RequireAndVerifyClientCert},
		{name: "no certificate", l: ListenerTLS{Protocol: "IMAP proxy", Name: "edge", CertFile: certFile},
			wantErr: "TLS enabled for IMAP proxy [edge] but no tls_cert_file/tls_key_file provided"},
		{name: "unreadable files", l: ListenerTLS{Protocol: "LMTP", Name: "in", CertFile: "/nonexistent.crt", KeyFile: keyFile},
			wantErr: "failed to load TLS certificate for LMTP [in]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := tc.l.Config()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Config() error = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Config(): %v", err)
			}
			if len(cfg.Certificates) != 1 || string(cfg.Certificates[0].Certificate[0]) != string(tc.wantCert) {
				t.Errorf("served certificate is not the expected one")
			}
			if !slices.Equal(cfg.NextProtos, tc.wantALPN) {
				t.Errorf("NextProtos = %v, want %v", cfg.NextProtos, tc.wantALPN)
			}
			if cfg.ClientAuth != tc.wantClient {
				t.Errorf("ClientAuth = %v, want %v", cfg.ClientAuth, tc.wantClient)
			}
			if cfg.MinVersion == 0 && tc.l.Global == nil {
				t.Errorf("MinVersion unset for a certificate from files")
			}
			if cfg == global {
				t.Errorf("Config() returned the shared global config itself")
			}
		})
	}
	// Every listener shares the global config: tls_verify on one must not
	// reach the others.
	if global.ClientAuth != tls.NoClientCert {
		t.Errorf("the global config was modified: ClientAuth = %v", global.ClientAuth)
	}
}
