package managesieve

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/foxcpp/go-sieve"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/server"
)

type ManageSieveSession struct {
	server.Session
	mutex         sync.Mutex
	server        *ManageSieveServer
	conn          *net.Conn          // Connection to the client
	*server.User                     // User associated with the session
	authenticated bool               // Flag to indicate if the user has been authenticated
	ctx           context.Context    // Context for this session
	cancel        context.CancelFunc // Function to cancel the session's context

	reader *bufio.Reader
	writer *bufio.Writer
	isTLS  bool
}

func (s *ManageSieveSession) sendRawLine(line string) {
	s.writer.WriteString(line + "\r\n")
}

func (s *ManageSieveSession) sendCapabilities() {
	s.sendRawLine(fmt.Sprintf("\"IMPLEMENTATION\" \"%s\"", "ManageSieve"))
	s.sendRawLine("\"SIEVE\" \"fileinto vacation\"")

	if s.server.tlsConfig != nil && s.server.useStartTLS && !s.isTLS {
		s.sendRawLine("\"STARTTLS\"")
	}
	if !s.isTLS && s.server.insecureAuth {
		s.sendRawLine("\"AUTH=PLAIN\"")
	}
	if s.server.maxScriptSize > 0 {
		s.sendRawLine(fmt.Sprintf("\"MAXSCRIPTSIZE\" \"%d\"", s.server.maxScriptSize))
	}
}

func (s *ManageSieveSession) handleConnection() {
	defer s.Close()

	s.sendCapabilitiesGreeting()

	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				s.Log("[MANAGESIEVE] client dropped connection")
			} else {
				s.Log("read error: %v", err)
			}
			return
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 3)
		command := strings.ToUpper(parts[0])

		switch command {
		case "CAPABILITY":
			s.handleCapability()

		case "LOGIN":
			if len(parts) < 3 {
				s.sendResponse("NO Syntax: LOGIN address password\r\n")
				continue
			}
			userAddress := parts[1]
			password := parts[2]

			address, err := server.NewAddress(userAddress)
			if err != nil {
				s.Log("error: %v", err)
				s.sendResponse("NO Invalid address\r\n")
				continue
			}

			userID, err := s.server.db.Authenticate(s.ctx, address.FullAddress(), password)
			if err != nil {
				s.sendResponse("NO Authentication failed\r\n")
				continue
			}
			s.Log("[MANAGESIEVE] user %s authenticated", address.FullAddress())
			s.authenticated = true
			s.User = server.NewUser(address, userID)
			s.sendResponse("OK Authenticated\r\n")

		case "LISTSCRIPTS":
			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				continue
			}
			s.handleListScripts()

		case "GETSCRIPT":
			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				continue
			}
			if len(parts) < 2 {
				s.sendResponse("NO Syntax: GETSCRIPT scriptName\r\n")
				continue
			}
			scriptName := parts[1]
			s.handleGetScript(scriptName)

		case "PUTSCRIPT":
			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				continue
			}
			if len(parts) < 3 {
				s.sendResponse("NO Syntax: PUTSCRIPT scriptName scriptContent\r\n")
				continue
			}
			scriptName := parts[1]
			scriptContent := parts[2]
			s.handlePutScript(scriptName, scriptContent)

		case "SETACTIVE":
			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				continue
			}
			if len(parts) < 2 {
				s.sendResponse("NO Syntax: SETACTIVE scriptName\r\n")
				continue
			}
			scriptName := parts[1]
			s.handleSetActive(scriptName)

		case "DELETESCRIPT":
			if !s.authenticated {
				s.sendResponse("NO Not authenticated\r\n")
				continue
			}
			if len(parts) < 2 {
				s.sendResponse("NO Syntax: DELETESCRIPT scriptName\r\n")
				continue
			}
			scriptName := parts[1]
			s.handleDeleteScript(scriptName)

		case "STARTTLS":
			if !s.server.useStartTLS || s.server.tlsConfig == nil {
				s.sendResponse("NO STARTTLS not supported\r\n")
				continue
			}
			if s.isTLS {
				s.sendResponse("NO TLS already active\r\n")
				continue
			}
			s.sendResponse("OK Begin TLS negotiation\r\n")

			// Upgrade the connection to TLS
			tlsConn := tls.Server(*s.conn, s.server.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				s.Log("[MANAGESIEVE] TLS handshake failed: %v", err)
				s.sendResponse("NO TLS handshake failed\r\n")
				continue
			}

			// Replace the connection and readers/writers
			*s.conn = tlsConn
			s.reader = bufio.NewReader(tlsConn)
			s.writer = bufio.NewWriter(tlsConn)
			s.isTLS = true
			s.Log("[MANAGESIEVE] TLS negotiation successful")

		case "NOOP":
			s.sendResponse("OK\r\n")

		case "LOGOUT":
			s.sendResponse("OK Goodbye\r\n")
			s.Close()
			return

		default:
			s.sendResponse("NO Unknown command\r\n")
		}
	}
}

func (s *ManageSieveSession) sendCapabilitiesGreeting() {
	s.sendCapabilities()

	implementationName := "Sora"
	var okMessage string
	// Check if STARTTLS is supported and not yet active for the (STARTTLS) hint in OK response
	if s.server.tlsConfig != nil && s.server.useStartTLS && !s.isTLS {
		okMessage = fmt.Sprintf("OK (STARTTLS) \"%s\" ManageSieve server ready.", implementationName)
	} else {
		okMessage = fmt.Sprintf("OK \"%s\" ManageSieve server ready.", implementationName)
	}
	s.sendRawLine(okMessage)
	s.writer.Flush() // Flush all greeting lines
}

func (s *ManageSieveSession) sendResponse(response string) {
	s.writer.WriteString(response)
	s.writer.Flush()
}

func (s *ManageSieveSession) handleCapability() {
	s.sendCapabilities()
	s.sendRawLine("OK")
	s.writer.Flush()
}

func (s *ManageSieveSession) handleListScripts() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	scripts, err := s.server.db.GetUserScripts(s.ctx, s.UserID())
	if err != nil {
		s.sendResponse("NO Internal server error\r\n")
		return
	}

	if len(scripts) == 0 {
		s.sendResponse("OK\r\n")
		return
	}

	for _, script := range scripts {
		line := fmt.Sprintf("\"%s\"", script.Name)
		if script.Active {
			line += " ACTIVE"
		}
		s.sendRawLine(line)
	}
	s.sendRawLine("OK")
	s.writer.Flush()
}

func (s *ManageSieveSession) handleGetScript(name string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	script, err := s.server.db.GetScriptByName(s.ctx, name, s.UserID())
	if err != nil {
		s.sendResponse("NO No such script\r\n")
		return
	}
	s.writer.WriteString(fmt.Sprintf("{%d}\r\n", len(script.Script)))
	s.writer.WriteString(script.Script)
	s.writer.Flush()
	s.sendResponse("OK\r\n")
}

func (s *ManageSieveSession) handlePutScript(name, content string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.server.maxScriptSize > 0 && int64(len(content)) > s.server.maxScriptSize {
		s.sendResponse(fmt.Sprintf("NO (MAXSCRIPTSIZE) Script size %d exceeds maximum allowed size %d\r\n", len(content), s.server.maxScriptSize))
		return
	}

	scriptReader := strings.NewReader(content)
	options := sieve.DefaultOptions()
	_, err := sieve.Load(scriptReader, options)
	if err != nil {
		s.sendResponse(fmt.Sprintf("NO Script validation failed: %v\r\n", err))
		return
	}

	script, err := s.server.db.GetScriptByName(s.ctx, name, s.UserID())
	if err != nil {
		if err != consts.ErrDBNotFound {
			s.sendResponse("NO Internal server error\r\n")
			return
		}
	}
	if script != nil {
		_, err := s.server.db.UpdateScript(s.ctx, script.ID, s.UserID(), name, content)
		if err != nil {
			s.sendResponse("NO Internal server error\r\n")
			return
		}
		s.sendResponse("OK Script updated\r\n")
		return
	}

	_, err = s.server.db.CreateScript(s.ctx, s.UserID(), name, content)
	if err != nil {
		s.sendResponse("NO Internal server error\r\n")
		return
	}
	s.sendResponse("OK Script stored\r\n")
}

func (s *ManageSieveSession) handleSetActive(name string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	script, err := s.server.db.GetScriptByName(s.ctx, name, s.UserID())
	if err != nil {
		if err == consts.ErrDBNotFound {
			s.sendResponse("NO No such script\r\n")
			return
		}
		s.sendResponse("NO Internal server error\r\n")
		return
	}

	// Validate the script before activating it
	scriptReader := strings.NewReader(script.Script)
	options := sieve.DefaultOptions()
	_, err = sieve.Load(scriptReader, options)
	if err != nil {
		s.sendResponse(fmt.Sprintf("NO Script validation failed: %v\r\n", err))
		return
	}

	err = s.server.db.SetScriptActive(s.ctx, script.ID, s.UserID(), true)
	if err != nil {
		s.sendResponse("NO Internal server error\r\n")
		return
	}

	s.sendResponse("OK Script activated\r\n")
}

func (s *ManageSieveSession) handleDeleteScript(name string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	script, err := s.server.db.GetScriptByName(s.ctx, name, s.UserID())
	if err != nil {
		if err == consts.ErrDBNotFound {
			s.sendResponse("NO No such script\r\n") // RFC uses NO for "No such script"
			return
		}
		s.sendResponse("NO Internal server error\r\n") // RFC uses NO for server errors
		return
	}

	err = s.server.db.DeleteScript(s.ctx, script.ID, s.UserID())
	if err != nil {
		s.sendResponse("NO Internal server error\r\n")
		return
	}
	s.sendResponse("OK Script deleted\r\n")
}

func (s *ManageSieveSession) Close() error {
	(*s.conn).Close()
	if s.User != nil {
		s.Log("closed")
		s.User = nil
		s.Id = ""
		s.authenticated = false
		if s.cancel != nil {
			s.cancel()
		}
	}
	return nil
}
