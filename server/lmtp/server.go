package lmtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

type LMTPServerBackend struct {
	addr          string
	hostname      string
	db            *db.Database
	s3            *storage.S3Storage
	uploader      *uploader.UploadWorker
	server        *smtp.Server
	appCtx        context.Context
	externalRelay string
	tlsConfig     *tls.Config

	// Connection counters
	totalConnections atomic.Int64
}

type LMTPServerOptions struct {
	ExternalRelay  string
	Debug          bool
	TLS            bool
	TLSCertFile    string
	TLSKeyFile     string
	TLSVerify      bool
	TLSUseStartTLS bool
}

func New(appCtx context.Context, hostname, addr string, s3 *storage.S3Storage, db *db.Database, uploadWorker *uploader.UploadWorker, options LMTPServerOptions) (*LMTPServerBackend, error) {
	backend := &LMTPServerBackend{
		addr:          addr,
		appCtx:        appCtx,
		hostname:      hostname,
		db:            db,
		s3:            s3,
		uploader:      uploadWorker,
		externalRelay: options.ExternalRelay,
	}

	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		backend.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true,
		}

		if !options.TLSVerify {
			backend.tlsConfig.InsecureSkipVerify = true
			log.Printf("WARNING: TLS certificate verification disabled for LMTP server")
		}
	}

	s := smtp.NewServer(backend)
	s.Addr = addr
	s.Domain = hostname
	s.AllowInsecureAuth = true
	s.LMTP = true

	// Configure StartTLS if enabled and TLS config is available
	if options.TLSUseStartTLS && backend.tlsConfig != nil {
		s.TLSConfig = backend.tlsConfig
		log.Printf("StartTLS is enabled")
		// Force AllowInsecureAuth to true when StartTLS is enabled
		// This is necessary because with StartTLS, initial connections are unencrypted
		s.AllowInsecureAuth = true
	}
	// We only use a TLS listener for implicit TLS, not for StartTLS

	backend.server = s

	s.Network = "tcp"

	var debugWriter io.Writer
	if options.Debug {
		debugWriter = os.Stdout
		s.Debug = debugWriter
	}

	return backend, nil
}

func (b *LMTPServerBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	sessionCtx, sessionCancel := context.WithCancel(b.appCtx)

	// Increment connection counters (in LMTP all connections are considered authenticated)
	b.totalConnections.Add(1)

	s := &LMTPSession{
		backend: b,
		conn:    c,
		ctx:     sessionCtx,
		cancel:  sessionCancel,
	}
	s.RemoteIP = c.Conn().RemoteAddr().String()
	s.Id = idgen.New()
	s.HostName = b.hostname
	s.Protocol = "LMTP"
	s.Stats = b // Set the server as the Stats provider

	// Create logging function for the mutex helper
	logFunc := func(format string, args ...interface{}) {
		s.Log(format, args...)
	}

	// Initialize the mutex helper
	s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, sessionCtx, "LMTP", logFunc)

	// Log connection with connection counters
	totalCount := b.totalConnections.Load()
	s.Log("new session remote=%s id=%s (connections: total=%d)",
		s.RemoteIP, s.Id, totalCount)

	return s, nil
}

func (b *LMTPServerBackend) Start(errChan chan error) {
	var listener net.Listener
	var err error

	// Only use a TLS listener if we're not using StartTLS and TLS is enabled
	if b.tlsConfig != nil && b.server.TLSConfig == nil {
		// Implicit TLS - use TLS listener
		listener, err = tls.Listen("tcp", b.server.Addr, b.tlsConfig)
		if err != nil {
			errChan <- fmt.Errorf("failed to create TLS listener: %w", err)
			return
		}
		log.Printf("* LMTP listening with implicit TLS on %s", b.server.Addr)
	} else {
		listener, err = net.Listen("tcp", b.server.Addr)
		if err != nil {
			errChan <- fmt.Errorf("failed to create listener: %w", err)
			return
		}
		log.Printf("* LMTP listening on %s", b.server.Addr)
	}
	defer listener.Close()

	if err := b.server.Serve(listener); err != nil {
		// Check if the error is due to context cancellation (graceful shutdown)
		if b.appCtx.Err() == nil {
			errChan <- fmt.Errorf("LMTP server error: %w", err)
		}
	}
}

func (b *LMTPServerBackend) Close() error {
	if b.server != nil {
		return b.server.Close()
	}
	return nil
}

// GetTotalConnections returns the current total connection count
func (b *LMTPServerBackend) GetTotalConnections() int64 {
	return b.totalConnections.Load()
}

// GetAuthenticatedConnections returns the current authenticated connection count
// For LMTP, all connections are considered authenticated
func (b *LMTPServerBackend) GetAuthenticatedConnections() int64 {
	return 0
}
