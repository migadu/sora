package imap

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/google/uuid"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/storage"
)

type IMAPServer struct {
	addr     string
	db       *db.Database
	hostname string
	s3       *storage.S3Storage
	server   *imapserver.Server
	caps     imap.CapSet
}

func New(hostname, imapAddr string, storage *storage.S3Storage, database *db.Database, insecureAuth bool, debug bool) (*IMAPServer, error) {
	s := &IMAPServer{
		hostname: hostname,
		addr:     imapAddr,
		db:       database,
		s3:       storage,
		caps: imap.CapSet{
			imap.CapIMAP4rev1: struct{}{},
			// imap.CapIMAP4rev2:   struct{}{},
			// imap.CapLiteralPlus: struct{}{},
			// imap.CapSASLIR:      struct{}{},
			// imap.CapAuthPlain:   struct{}{},
			// imap.CapMove:        struct{}{},
			// imap.CapIdle:        struct{}{},
			// imap.CapID:          struct{}{},
		},
	}

	var debugWriter io.Writer
	if debug {
		debugWriter = os.Stdout
	}

	s.server = imapserver.New(&imapserver.Options{
		NewSession:   s.newSession,
		Logger:       log.Default(),
		InsecureAuth: insecureAuth,
		DebugWriter:  debugWriter,
		Caps:         s.caps,
	})

	return s, nil
}

func (s *IMAPServer) newSession(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	session := &IMAPSession{
		server: s,
		conn:   conn,
	}

	session.RemoteIP = conn.NetConn().RemoteAddr().String()
	session.Protocol = "IMAP"
	session.Id = uuid.New().String()
	session.HostName = s.hostname

	greeting := &imapserver.GreetingData{
		PreAuth: false,
	}

	return session, greeting, nil
}

func (s *IMAPServer) Serve(imapAddr string) error {
	listener, err := net.Listen("tcp", imapAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	defer listener.Close()

	log.Printf("IMAP listening on %s", imapAddr)
	return s.server.Serve(listener)
}

func (s *IMAPServer) Close() {
	s.db.Close()
}
