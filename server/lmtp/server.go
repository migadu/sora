package lmtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/migadu/sora/db"
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
}

type LMTPServerOptions struct {
	ExternalRelay      string
	InsecureAuth       bool
	Debug              bool
	TLSCertFile        string
	TLSKeyFile         string
	InsecureSkipVerify bool
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

	if options.TLSCertFile != "" && options.TLSKeyFile != "" {
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

		if options.InsecureSkipVerify {
			backend.tlsConfig.InsecureSkipVerify = true
			log.Printf("[LMTP] WARNING: TLS certificate verification disabled for LMTP server")
		}
	}

	s := smtp.NewServer(backend)
	s.Addr = addr
	s.Domain = hostname
	s.AllowInsecureAuth = true
	s.LMTP = true
	s.TLSConfig = backend.tlsConfig

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
	s := &LMTPSession{
		backend: b,
		conn:    c,
		ctx:     sessionCtx,
		cancel:  sessionCancel,
	}
	s.RemoteIP = c.Conn().RemoteAddr().String()
	s.Id = uuid.New().String()
	s.HostName = b.hostname
	s.Protocol = "LMTP"

	s.Log("[LMTP] new session remote=%s id=%s", s.RemoteIP, s.Id)

	return s, nil
}

func (b *LMTPServerBackend) Start(errChan chan error) {
	log.Printf("* LMTP listening on %s", b.server.Addr)
	if err := b.server.ListenAndServe(); err != nil {
		// Check if the error is due to context cancellation (graceful shutdown)
		// b.appCtx.Err() will be non-nil if the context was canceled.
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
