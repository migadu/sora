package managesieve

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
)

// newServerForConfig builds a ManageSieve server from a [[server]] block the way
// cmd/sora does at start-up.
func newServerForConfig(t *testing.T, cfg config.ServerConfig, opts ManageSieveServerOptions) *ManageSieveServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	opts.MaxScriptSize = cfg.GetMaxScriptSizeWithDefault() // as startDynamicManageSieveServer
	opts.CommandTimeout = time.Minute
	opts.MaxConnections = 10
	opts.Config = &config.Config{}
	srv, err := New(ctx, cfg.Name, "localhost", "127.0.0.1:0", &resilient.ResilientDatabase{}, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// dialManageSieve opens a connection served by the library server a new connection
// gets (the one a reload swaps in), as Start's accept loop does, and returns it with
// the greeting's capability lines read.
func dialManageSieve(t *testing.T, srv *ManageSieveServer) (net.Conn, *bufio.Reader, []string) {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := serverPkg.NewSoraListenerFunc(tcp, srv.connConfig)
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		srv.msLibServer.Load().ServeConn(conn)
	}()

	conn, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	var greeting []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading the greeting: %v", err)
		}
		if strings.HasPrefix(line, "OK") {
			return conn, reader, greeting
		}
		greeting = append(greeting, strings.TrimRight(line, "\r\n"))
	}
}

// advertisedMaxScriptSize returns the MAXSCRIPTSIZE a new connection is offered,
// "" when it is not advertised (go-managesieve then applies no limit).
func advertisedMaxScriptSize(t *testing.T, srv *ManageSieveServer) string {
	t.Helper()
	_, _, greeting := dialManageSieve(t, srv)
	for _, line := range greeting {
		if v, ok := strings.CutPrefix(line, `"MAXSCRIPTSIZE" `); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// scriptSizeLogs is a log sink that is safe for the server's goroutines to write to.
type scriptSizeLogs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *scriptSizeLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *scriptSizeLogs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// max_script_size is the same limit at start-up and after a SIGHUP (#336): "0", like an
// omitted value, is the 16 KiB default in both places, never "no limit" (go-managesieve's
// meaning of 0, which also stops advertising MAXSCRIPTSIZE). A reload that leaves the
// value as it was does not report it as reloaded, and one that does not parse keeps the
// running limit and says so.
func TestMaxScriptSizeSameAtStartupAndAfterReload(t *testing.T) {
	logs := &scriptSizeLogs{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { logger.Swap(prev) })

	const def = DefaultMaxScriptSize
	for _, tt := range []struct {
		name          string
		start, reload string
		wantStart     int64
		wantReload    int64
		wantReloaded  bool
		wantWarn      bool
	}{
		{name: "zero unchanged", start: "0", reload: "0", wantStart: def, wantReload: def},
		{name: "zero with a unit unchanged", start: "0kb", reload: "0kb", wantStart: def, wantReload: def},
		{name: "omitted unchanged", start: "", reload: "", wantStart: def, wantReload: def},
		{name: "explicit unchanged", start: "32kb", reload: "32kb", wantStart: 32 << 10, wantReload: 32 << 10},
		{name: "explicit to zero", start: "32kb", reload: "0", wantStart: 32 << 10, wantReload: def, wantReloaded: true},
		{name: "zero to explicit", start: "0", reload: "64kb", wantStart: def, wantReload: 64 << 10, wantReloaded: true},
		{name: "unparsable keeps the running limit", start: "32kb", reload: "32 kilobytes", wantStart: 32 << 10, wantReload: 32 << 10, wantWarn: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			name := "sieve-" + strings.ReplaceAll(tt.name, " ", "-")
			srv := newServerForConfig(t, config.ServerConfig{Name: name, Type: "managesieve", MaxScriptSize: tt.start}, ManageSieveServerOptions{})
			if got := srv.settings.Load().maxScriptSize; got != tt.wantStart {
				t.Fatalf("max_script_size %q at start-up = %d, want %d", tt.start, got, tt.wantStart)
			}
			if got, want := advertisedMaxScriptSize(t, srv), strconv.FormatInt(tt.wantStart, 10); got != want {
				t.Fatalf("MAXSCRIPTSIZE at start-up = %q, want %q", got, want)
			}

			logsBefore := len(logs.String())
			if err := srv.ReloadConfig(config.ServerConfig{Name: name, Type: "managesieve", MaxScriptSize: tt.reload}); err != nil {
				t.Fatal(err)
			}
			logged := logs.String()[logsBefore:]

			if got := srv.settings.Load().maxScriptSize; got != tt.wantReload {
				t.Errorf("max_script_size %q after reloading %q = %d, want %d", tt.start, tt.reload, got, tt.wantReload)
			}
			if got, want := advertisedMaxScriptSize(t, srv), strconv.FormatInt(tt.wantReload, 10); got != want {
				t.Errorf("MAXSCRIPTSIZE after reloading %q = %q, want %q", tt.reload, got, want)
			}
			// The other settings this reload does not mention may be reported; only
			// max_script_size is looked at.
			reported, warned := false, false
			for _, line := range strings.Split(logged, "\n") {
				if !strings.Contains(line, "max_script_size") || !strings.Contains(line, "name="+name) {
					continue
				}
				if strings.Contains(line, "config reloaded") {
					reported = true
				}
				if strings.Contains(line, "level=WARN") && strings.Contains(line, "error=") &&
					strings.Contains(line, "running="+strconv.FormatInt(tt.wantStart, 10)) {
					warned = true
				}
			}
			if reported != tt.wantReloaded {
				t.Errorf("reloading %q over %q reported max_script_size as reloaded: %v, want %v; logged:\n%s", tt.reload, tt.start, reported, tt.wantReloaded, logged)
			}
			if warned != tt.wantWarn {
				t.Errorf("WARN naming max_script_size and the kept limit: %v, want %v; logged:\n%s", warned, tt.wantWarn, logged)
			}
		})
	}
}
