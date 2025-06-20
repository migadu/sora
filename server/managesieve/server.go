package managesieve

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync/atomic"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
)

const DefaultMaxScriptSize = 16 * 1024 // 16 KB

type ManageSieveServer struct {
	addr          string
	hostname      string
	db            *db.Database
	appCtx        context.Context
	tlsConfig     *tls.Config
	useStartTLS   bool
	insecureAuth  bool
	maxScriptSize int64

	// Connection counters
	totalConnections         atomic.Int64
	authenticatedConnections atomic.Int64
}

type ManageSieveServerOptions struct {
	InsecureAuth   bool
	Debug          bool
	TLS            bool
	TLSCertFile    string
	TLSKeyFile     string
	TLSVerify      bool
	TLSUseStartTLS bool
	MaxScriptSize  int64
}

func New(appCtx context.Context, hostname, addr string, database *db.Database, options ManageSieveServerOptions) (*ManageSieveServer, error) {
	server := &ManageSieveServer{
		hostname:      hostname,
		addr:          addr,
		db:            database,
		appCtx:        appCtx,
		useStartTLS:   options.TLSUseStartTLS,
		insecureAuth:  options.InsecureAuth,
		maxScriptSize: options.MaxScriptSize,
	}

	// Set up TLS config if TLS is enabled and certificates are provided
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		server.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true,
		}

		if !options.TLSVerify {
			server.tlsConfig.InsecureSkipVerify = true
			log.Printf("WARNING: TLS certificate verification disabled for ManageSieve server")
		}
	}

	return server, nil
}

func (s *ManageSieveServer) Start(errChan chan error) {
	var listener net.Listener
	var err error

	isImplicitTLS := s.tlsConfig != nil && !s.useStartTLS
	// Only use a TLS listener if we're not using StartTLS and TLS is enabled
	if isImplicitTLS {
		// Implicit TLS - use TLS listener
		listener, err = tls.Listen("tcp", s.addr, s.tlsConfig)
		if err != nil {
			errChan <- fmt.Errorf("failed to create TLS listener: %w", err)
			return
		}
		log.Printf("* ManageSieve listening with implicit TLS on %s", s.addr)
	} else {
		listener, err = net.Listen("tcp", s.addr)
		if err != nil {
			errChan <- fmt.Errorf("failed to create listener: %w", err)
			return
		}
		log.Printf("* ManageSieve listening on %s", s.addr)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}

		// Increment total connections counter
		totalCount := s.totalConnections.Add(1)
		authCount := s.authenticatedConnections.Load()

		sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

		session := &ManageSieveSession{
			server: s,
			conn:   &conn,
			reader: bufio.NewReader(conn),
			writer: bufio.NewWriter(conn),
			ctx:    sessionCtx,
			cancel: sessionCancel,
			isTLS:  isImplicitTLS, // Initialize isTLS based on the listener type
		}

		// Create logging function for the mutex helper
		logFunc := func(format string, args ...interface{}) {
			session.Log(format, args...)
		}

		// Initialize the mutex helper
		session.mutexHelper = server.NewMutexTimeoutHelper(&session.mutex, sessionCtx, "MANAGESIEVE", logFunc)

		session.RemoteIP = (*session.conn).RemoteAddr().String()
		session.Protocol = "ManageSieve"
		session.Id = idgen.New()
		session.HostName = session.server.hostname
		session.Stats = s // Set the server as the Stats provider

		// Log connection with connection counters
		log.Printf("* ManageSieve new connection from %s (connections: total=%d, authenticated=%d)",
			session.RemoteIP, totalCount, authCount)

		go session.handleConnection()
	}
}

func (s *ManageSieveServer) Close() {
	// The shared database connection pool is closed by main.go's defer.
	// If ManageSieveServer had its own specific resources to close (e.g., a listener, which it doesn't),
	// they would be closed here. For now, this can be a no-op or just log.
}

// GetTotalConnections returns the current total connection count
func (s *ManageSieveServer) GetTotalConnections() int64 {
	return s.totalConnections.Load()
}

// GetAuthenticatedConnections returns the current authenticated connection count
func (s *ManageSieveServer) GetAuthenticatedConnections() int64 {
	return s.authenticatedConnections.Load()
}
