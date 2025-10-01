package server

import (
	"crypto/tls"
	"log"
	"net"
	"sync"

	"github.com/exaring/ja4plus"
)

// ja4TLSListener wraps a TLS listener to capture JA4 fingerprints via GetConfigForClient
type ja4TLSListener struct {
	net.Listener
	baseConfig *tls.Config
}

// NewJA4TLSListener creates a new JA4-enabled TLS listener
func NewJA4TLSListener(inner net.Listener, config *tls.Config) net.Listener {
	// Clone the config to avoid modifying the original
	newConfig := config.Clone()

	listener := &ja4TLSListener{
		Listener:   inner,
		baseConfig: newConfig,
	}

	return listener
}

// Accept accepts a connection and wraps it for JA4 capture
func (l *ja4TLSListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Create a wrapped connection that will capture JA4 during handshake
	ja4Conn := &ja4CaptureConn{
		baseConn:   conn,
		baseConfig: l.baseConfig,
	}

	// Set up GetConfigForClient callback to capture JA4 fingerprint
	configWithCapture := l.baseConfig.Clone()
	configWithCapture.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		// Generate JA4 fingerprint from ClientHelloInfo
		fingerprint := ja4plus.JA4(info)

		// Store it in the connection wrapper
		ja4Conn.mu.Lock()
		ja4Conn.ja4Fingerprint = fingerprint
		ja4Conn.mu.Unlock()

		log.Printf("[JA4] Captured fingerprint during handshake: %s", fingerprint)

		// Call original GetConfigForClient if it exists
		if l.baseConfig.GetConfigForClient != nil {
			return l.baseConfig.GetConfigForClient(info)
		}

		// Return nil to use the current config
		return nil, nil
	}

	// Create TLS server connection with our capturing config
	tlsConn := tls.Server(conn, configWithCapture)
	ja4Conn.Conn = tlsConn

	return ja4Conn, nil
}

// ja4CaptureConn wraps a TLS connection and stores the captured JA4 fingerprint
type ja4CaptureConn struct {
	*tls.Conn
	baseConn       net.Conn
	baseConfig     *tls.Config
	ja4Fingerprint string
	mu             sync.Mutex
}

// GetJA4Fingerprint returns the captured JA4 fingerprint
func (c *ja4CaptureConn) GetJA4Fingerprint() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ja4Fingerprint == "" {
		return "", nil // Not captured yet or handshake not complete
	}

	return c.ja4Fingerprint, nil
}

// GetClientHello returns the JA4 fingerprint (we don't have raw bytes with this approach)
func (c *ja4CaptureConn) GetClientHello() []byte {
	// With ja4plus library, we don't have raw ClientHello bytes
	// We only have the parsed fingerprint
	return nil
}
