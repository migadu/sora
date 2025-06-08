package pop3

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/google/uuid"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

type POP3Server struct {
	addr      string
	hostname  string
	db        *db.Database
	s3        *storage.S3Storage
	appCtx    context.Context
	cancel    context.CancelFunc // Cancel function for the app context
	uploader  *uploader.UploadWorker
	cache     *cache.Cache
	tlsConfig *tls.Config
}

type POP3ServerOptions struct {
	Debug       bool
	TLS         bool
	TLSCertFile string
	TLSKeyFile  string
	TLSVerify   bool
}

func New(appCtx context.Context, hostname, popAddr string, storage *storage.S3Storage, database *db.Database, uploadWorker *uploader.UploadWorker, cache *cache.Cache, options POP3ServerOptions) (*POP3Server, error) {
	// Create a new context with a cancel function for clean shutdown
	serverCtx, serverCancel := context.WithCancel(appCtx)

	server := &POP3Server{
		hostname: hostname,
		addr:     popAddr,
		db:       database,
		s3:       storage,
		appCtx:   serverCtx,
		cancel:   serverCancel,
		uploader: uploadWorker,
		cache:    cache,
	}

	// Setup TLS if TLS is enabled and certificate and key files are provided
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		server.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12, // Allow older TLS versions for better compatibility
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true, // Prefer server cipher suites over client cipher suites
		}

		// Set InsecureSkipVerify if requested (for self-signed certificates)
		if !options.TLSVerify {
			server.tlsConfig.InsecureSkipVerify = true
			log.Printf("WARNING: TLS certificate verification disabled for POP3 server")
		}
	}

	return server, nil
}

func (s *POP3Server) Start(errChan chan error) {
	var listener net.Listener
	var err error

	if s.tlsConfig != nil {
		listener, err = tls.Listen("tcp", s.addr, s.tlsConfig)
		if err != nil {
			errChan <- fmt.Errorf("failed to create TLS listener: %w", err)
			return
		}
		log.Printf("* POP3 listening with TLS on %s", s.addr)
	} else {
		listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			errChan <- fmt.Errorf("failed to create listener: %w", err)
			return
		}
		log.Printf("* POP3 listening on %s", s.addr)
	}
	defer listener.Close()

	// Use a goroutine to monitor application context cancellation
	go func() {
		<-s.appCtx.Done()
		log.Printf("* POP3 server shutting down due to context cancellation")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Check if the error is due to the listener being closed
			if s.appCtx.Err() != nil {
				log.Printf("* POP3 server closed: %v", s.appCtx.Err())
				return
			}
			errChan <- err
			return
		}

		// Create a new context for this session that inherits from app context
		sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

		session := &POP3Session{
			server:  s,
			conn:    &conn,
			deleted: make(map[int]bool),
			ctx:     sessionCtx,
			cancel:  sessionCancel,
		}

		session.RemoteIP = (*session.conn).RemoteAddr().String()
		session.Protocol = "POP3"
		session.Id = uuid.New().String()
		session.HostName = s.hostname

		go session.handleConnection()
	}
}

func (s *POP3Server) Close() {
	log.Printf("* POP3 server closing")
	// Cancel the app context if it's still active
	// This will propagate to all session contexts
	if s.cancel != nil {
		s.cancel()
	}
	if s.db != nil {
		s.db.Close()
	}
}
