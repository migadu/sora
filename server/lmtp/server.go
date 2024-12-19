package lmtp

import (
	"io"
	"log"
	"os"

	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/storage"
)

type LMTPServerBackend struct {
	addr     string
	hostname string
	db       *db.Database
	s3       *storage.S3Storage
	server   *smtp.Server
}

func New(hostname, addr string, s3 *storage.S3Storage, db *db.Database, debug bool, errChan chan error) *smtp.Server {
	backend := &LMTPServerBackend{
		addr:     addr,
		hostname: hostname,
		db:       db,
		s3:       s3,
	}
	s := smtp.NewServer(backend)
	s.Addr = addr
	s.Domain = hostname
	s.AllowInsecureAuth = true
	s.LMTP = true

	// Save the server instance in the backend
	backend.server = s

	// This server supports only TCP connections
	s.Network = "tcp"

	var debugWriter io.Writer
	if debug {
		debugWriter = os.Stdout
		s.Debug = debugWriter
	}

	log.Printf("LMTP listening on %s", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		errChan <- err
	}

	return s
}

func (b *LMTPServerBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	s := &LMTPSession{
		backend: b,
		conn:    c,
	}
	s.RemoteIP = c.Conn().RemoteAddr().String()
	s.Id = uuid.New().String()
	s.HostName = b.hostname
	s.Protocol = "LMTP"

	s.Log("New session")
	return s, nil
}
