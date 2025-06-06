package managesieve

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"

	"github.com/google/uuid"
	"github.com/migadu/sora/db"
)

type ManageSieveServer struct {
	addr      string
	hostname  string
	db        *db.Database
	appCtx    context.Context
	tlsConfig *tls.Config
}

type ManageSieveServerOptions struct {
	InsecureAuth       bool
	Debug              bool
	TLSCertFile        string
	TLSKeyFile         string
	InsecureSkipVerify bool
}

func New(appCtx context.Context, hostname, addr string, database *db.Database, options ManageSieveServerOptions) (*ManageSieveServer, error) {
	server := &ManageSieveServer{
		hostname: hostname,
		addr:     addr,
		db:       database,
		appCtx:   appCtx,
	}

	if options.TLSCertFile != "" && options.TLSKeyFile != "" {
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

		if options.InsecureSkipVerify {
			server.tlsConfig.InsecureSkipVerify = true
			log.Printf("WARNING: TLS certificate verification disabled for ManageSieve server")
		}
	}

	return server, nil
}

func (s *ManageSieveServer) Start(errChan chan error) {
	var listener net.Listener
	var err error

	if s.tlsConfig != nil {
		listener, err = tls.Listen("tcp", s.addr, s.tlsConfig)
		if err != nil {
			errChan <- fmt.Errorf("failed to create TLS listener: %w", err)
			return
		}
		log.Printf("* ManageSieve listening with TLS on %s", s.addr)
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

		sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

		session := &ManageSieveSession{
			server: s,
			conn:   &conn,
			reader: bufio.NewReader(conn),
			writer: bufio.NewWriter(conn),
			ctx:    sessionCtx,
			cancel: sessionCancel,
		}

		session.RemoteIP = (*session.conn).RemoteAddr().String()
		session.Protocol = "ManageSieve"
		session.Id = uuid.New().String()
		session.HostName = session.server.hostname

		go session.handleConnection()
	}
}

func (s *ManageSieveServer) Close() {
	// The shared database connection pool is closed by main.go's defer.
	// If ManageSieveServer had its own specific resources to close (e.g., a listener, which it doesn't),
	// they would be closed here. For now, this can be a no-op or just log.
}
