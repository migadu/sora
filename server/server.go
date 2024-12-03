package server

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/storage"
)

type SoraServer struct {
	db     *db.Database
	s3     *storage.S3Storage
	server *imapserver.Server
	caps   imap.CapSet
}

func New(storage *storage.S3Storage, database *db.Database, insecureAuth *bool, debug *bool) (*SoraServer, error) {
	s := &SoraServer{
		db: database,
		s3: storage,
		caps: imap.CapSet{
			// imap.CapIMAP4rev1:   struct{}{},
			imap.CapIMAP4rev2:   struct{}{},
			imap.CapLiteralPlus: struct{}{},
			imap.CapSASLIR:      struct{}{},
			imap.CapAuthPlain:   struct{}{},
			imap.CapMove:        struct{}{},
			imap.CapIdle:        struct{}{},
			imap.CapID:          struct{}{},

			// Add other capabilities as needed
		},
	}

	var debugWriter io.Writer
	if *debug {
		debugWriter = os.Stdout
	}

	s.server = imapserver.New(&imapserver.Options{
		NewSession:   s.newSession,
		Logger:       log.Default(),
		InsecureAuth: *insecureAuth,
		DebugWriter:  debugWriter,
		Caps:         s.caps,
	})

	return s, nil
}

func (s *SoraServer) Serve(imapAddr *string) error {
	listener, err := net.Listen("tcp", *imapAddr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	defer listener.Close()

	log.Printf("IMAP server listening on %s", listener.Addr())
	return s.server.Serve(listener)
}

func (s *SoraServer) Close() {
	s.db.Close()
}

func (s *SoraServer) newSession(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	session := &SoraSession{
		server: s,
		conn:   conn,
	}

	greeting := &imapserver.GreetingData{
		PreAuth: false,
	}

	return session, greeting, nil
}
