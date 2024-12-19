package pop3

import (
	"log"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/storage"
)

const MAX_ERRORS_ALLOWED = 3
const ERROR_DELAY = 3 * time.Second
const IDLE_TIMEOUT = 5 * time.Minute // Maximum duration of inactivity before the connection is closed

type POP3Server struct {
	addr     string
	hostname string
	db       *db.Database
	s3       *storage.S3Storage
}

func New(hostname, popAddr string, storage *storage.S3Storage, database *db.Database, insecureAuth bool, debug bool) (*POP3Server, error) {
	return &POP3Server{
		hostname: hostname,
		addr:     popAddr,
		db:       database,
		s3:       storage,
	}, nil
}

func (s *POP3Server) Start(errChan chan error) {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		errChan <- err
		return
	}
	defer ln.Close()

	log.Printf("POP3 listening on %s", s.addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			errChan <- err
			return
		}

		s := &POP3Session{
			server:  s,
			conn:    &conn,
			deleted: make(map[int]bool),
		}

		s.RemoteIP = (*s.conn).RemoteAddr().String()
		s.Protocol = "POP3"
		s.Id = uuid.New().String()
		s.HostName = s.server.hostname

		go s.handleConnection()
	}
}

func (s *POP3Server) Close() {
	s.db.Close()
}
