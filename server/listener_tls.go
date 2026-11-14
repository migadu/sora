package server

import (
	"crypto/tls"
	"fmt"

	"github.com/migadu/sora/logger"
)

// ListenerTLS is where a [[server]] listener with tls = true gets its
// certificate, and whether it requires one from its clients.
type ListenerTLS struct {
	Protocol string      // the listener type in logs and errors, e.g. "IMAP proxy"
	Name     string      // the [[server]] name
	CertFile string      // tls_cert_file
	KeyFile  string      // tls_key_file
	Verify   bool        // tls_verify
	Global   *tls.Config // the global [tls] manager's config; nil when [tls] is disabled
	ALPN     []string    // NextProtos offered with a certificate from CertFile/KeyFile
}

// Config returns the TLS config the listener serves with, by one rule for
// every listener type:
//
//   - With the global [tls] manager enabled, its certificate. The listener's
//     tls_cert_file/tls_key_file are then ignored, with a warning naming them.
//   - Otherwise the listener's tls_cert_file/tls_key_file.
//   - With neither, an error: a listener with tls = true never comes up
//     plaintext.
//
// tls_verify = true requires and verifies a client certificate whichever of
// the two supplied the server's. The global config is cloned, never modified:
// every listener shares it.
func (l ListenerTLS) Config() (*tls.Config, error) {
	var cfg *tls.Config
	switch {
	case l.Global != nil:
		if l.CertFile != "" || l.KeyFile != "" {
			logger.Warn("tls_cert_file/tls_key_file ignored: the global [tls] certificate is used", "protocol", l.Protocol, "name", l.Name, "tls_cert_file", l.CertFile, "tls_key_file", l.KeyFile)
		}
		cfg = l.Global.Clone()
	case l.CertFile != "" && l.KeyFile != "":
		cert, err := tls.LoadX509KeyPair(l.CertFile, l.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate for %s [%s]: %w", l.Protocol, l.Name, err)
		}
		if len(cert.Certificate) < 2 {
			logger.Debug("TLS certificate file holds a single certificate; it should hold the full chain", "protocol", l.Protocol, "name", l.Name, "tls_cert_file", l.CertFile)
		}
		cfg = &tls.Config{
			Certificates:  []tls.Certificate{cert},
			MinVersion:    tls.VersionTLS12,
			NextProtos:    l.ALPN,
			Renegotiation: tls.RenegotiateNever,
		}
	default:
		return nil, fmt.Errorf("TLS enabled for %s [%s] but no tls_cert_file/tls_key_file provided and no global TLS manager configured", l.Protocol, l.Name)
	}

	cfg.ClientAuth = tls.NoClientCert
	if l.Verify {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
