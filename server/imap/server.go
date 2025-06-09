package imap

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/idgen"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

const DefaultAppendLimit = 25 * 1024 * 1024 // 25MB

type IMAPServer struct {
	addr               string
	db                 *db.Database
	hostname           string
	s3                 *storage.S3Storage
	server             *imapserver.Server
	uploader           *uploader.UploadWorker
	cache              *cache.Cache
	appCtx             context.Context
	caps               imap.CapSet
	tlsConfig          *tls.Config
	masterUsername     string
	masterPassword     string
	masterSASLUsername string
	masterSASLPassword string
	appendLimit        int64
}

type IMAPServerOptions struct {
	Debug              bool
	TLS                bool
	TLSCertFile        string
	TLSKeyFile         string
	TLSVerify          bool
	MasterUsername     string
	MasterPassword     string
	MasterSASLUsername string
	MasterSASLPassword string
	AppendLimit        int64
}

func New(appCtx context.Context, hostname, imapAddr string, storage *storage.S3Storage, database *db.Database, uploadWorker *uploader.UploadWorker, cache *cache.Cache, options IMAPServerOptions) (*IMAPServer, error) {
	s := &IMAPServer{
		hostname:    hostname,
		appCtx:      appCtx,
		addr:        imapAddr,
		db:          database,
		s3:          storage,
		uploader:    uploadWorker,
		cache:       cache,
		appendLimit: options.AppendLimit,
		caps: imap.CapSet{
			imap.CapIMAP4rev1:   struct{}{},
			imap.CapLiteralPlus: struct{}{},
			imap.CapSASLIR:      struct{}{},
			imap.CapAuthPlain:   struct{}{},
			imap.CapMove:        struct{}{},
			imap.CapIdle:        struct{}{},
			imap.CapUIDPlus:     struct{}{},
			imap.CapESearch:     struct{}{},
			imap.CapESort:       struct{}{},
			imap.CapSort:        struct{}{},
			imap.CapSortDisplay: struct{}{},
			imap.CapSpecialUse:  struct{}{},
			imap.CapListStatus:  struct{}{},
			imap.CapBinary:      struct{}{},
			imap.CapCondStore:   struct{}{},
			imap.CapChildren:    struct{}{},
			imap.CapID:          struct{}{},
		},
		masterUsername:     options.MasterUsername,
		masterPassword:     options.MasterPassword,
		masterSASLUsername: options.MasterSASLUsername,
		masterSASLPassword: options.MasterSASLPassword,
	}

	if s.appendLimit > 0 {
		appendLimitCapName := imap.Cap(fmt.Sprintf("APPENDLIMIT=%d", s.appendLimit))
		s.caps[appendLimitCapName] = struct{}{}
		s.caps.Has(imap.CapAppendLimit)
	}

	// Setup TLS if TLS is enabled and certificate and key files are provided
	if options.TLS && options.TLSCertFile != "" && options.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(options.TLSCertFile, options.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
		}
		s.tlsConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12, // Allow older TLS versions for better compatibility
			ClientAuth:               tls.NoClientCert,
			ServerName:               hostname,
			PreferServerCipherSuites: true, // Prefer server cipher suites over client cipher suites
		}

		if !options.TLSVerify {
			s.tlsConfig.InsecureSkipVerify = true
			log.Printf("WARNING TLS certificate verification disabled for IMAP server")
		}
	}

	var debugWriter io.Writer
	if options.Debug {
		debugWriter = os.Stdout
	}

	s.server = imapserver.New(&imapserver.Options{
		NewSession:   s.newSession,
		Logger:       log.Default(),
		InsecureAuth: !options.TLS,
		DebugWriter:  debugWriter,
		Caps:         s.caps,
		TLSConfig:    s.tlsConfig,
	})

	return s, nil
}

func (s *IMAPServer) newSession(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	sessionCtx, sessionCancel := context.WithCancel(s.appCtx)

	session := &IMAPSession{
		server: s,
		conn:   conn,
		ctx:    sessionCtx,
		cancel: sessionCancel,
	}

	session.RemoteIP = conn.NetConn().RemoteAddr().String()
	session.Protocol = "IMAP"
	session.Id = idgen.New()
	session.HostName = s.hostname
	session.mutexHelper = serverPkg.NewMutexTimeoutHelper(&session.mutex, sessionCtx, "IMAP", session.Log)

	greeting := &imapserver.GreetingData{
		PreAuth: false,
	}

	session.Log("connected")

	return session, greeting, nil
}

func (s *IMAPServer) Serve(imapAddr string) error {
	var listener net.Listener
	var err error

	if s.tlsConfig != nil {
		listener, err = tls.Listen("tcp", imapAddr, s.tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to create TLS listener: %w", err)
		}
		log.Printf("* IMAP listening with TLS on %s", imapAddr)
	} else {
		listener, err = net.Listen("tcp", imapAddr)
		if err != nil {
			return fmt.Errorf("failed to create listener: %w", err)
		}
		log.Printf("* IMAP listening on %s", imapAddr)
	}
	defer listener.Close()

	return s.server.Serve(listener)
}

func (s *IMAPServer) Close() {
	if s.server != nil {
		// This will close the listener and cause s.server.Serve(listener) to return.
		// It will also start closing active client connections.
		s.server.Close()
	}
}
