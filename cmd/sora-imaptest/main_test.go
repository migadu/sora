package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/migadu/sora/internal/imaptest"
)

func noPassword(string) (string, bool) { return "", false }

func TestListNeedsNoServerOrCredentials(t *testing.T) {
	var out, stderr bytes.Buffer
	code := run(context.Background(), []string{"-list", "-run", "^search/", "-format", "json"}, &out, &stderr, noPassword)
	if code != 0 {
		t.Fatalf("list exited %d: %s", code, &stderr)
	}
	var cases []struct {
		Name string `json:"name"`
		RFC  string `json:"rfc"`
	}
	if err := json.Unmarshal(out.Bytes(), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 4 {
		t.Fatalf("missing search cases: %s", &out)
	}
	for _, c := range cases {
		if !strings.HasPrefix(c.Name, "search/") || c.RFC == "" {
			t.Fatalf("unexpected listed case: %+v", c)
		}
	}
}

func TestCLIRejectsInvalidInputsWithoutConnecting(t *testing.T) {
	for _, args := range [][]string{
		{"-run", "["}, {"-list", "-run", "^absent$"}, {"-format", "xml"}, {"-addr", ""},
		{"-user", ""}, {"-timeout", "-1s"}, {"positional"},
		{"-password-env", "MISSING_PASSWORD"}, {"-password-env", "SORA_IMAPTEST_PASSWORD"},
		{"-list", "-clients", "0"}, {"-list", "-clients", "-1"}, {"-list", "-clients", "1025"},
	} {
		var out, stderr bytes.Buffer
		if code := run(context.Background(), args, &out, &stderr, noPassword); code != 2 {
			t.Errorf("args %v: exit %d, want 2", args, code)
		}
	}
	var out, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-help"}, &out, &stderr, noPassword); code != 0 {
		t.Errorf("help exit %d", code)
	}
	for _, want := range []string{`(default "localhost:143")`, `(default "alice@example.com")`, `(default "none")`, `password "password"`} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("help omits seeded default %s: %s", want, &stderr)
		}
	}
}

func TestCLISeededDefaultsAndPasswordOverrides(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		env      map[string]string
		username string
		password string
	}{
		{name: "seed", username: "alice@example.com", password: "password"},
		{name: "default environment", env: map[string]string{"SORA_IMAPTEST_PASSWORD": "env-password"}, username: "alice@example.com", password: "env-password"},
		{name: "empty environment", env: map[string]string{"SORA_IMAPTEST_PASSWORD": ""}, username: "alice@example.com"},
		{name: "selected environment and user", args: []string{"-password-env", "CUSTOM_PASSWORD", "-user", "other@example.com"}, env: map[string]string{"CUSTOM_PASSWORD": "custom-password", "SORA_IMAPTEST_PASSWORD": "unused"}, username: "other@example.com", password: "custom-password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := cliEndpoint(t, false, "LOGIN "+imaptest.Quote(tc.username)+" "+imaptest.Quote(tc.password))
			args := append([]string{"-addr", addr, "-clients", "4", "-run", "^core/capability-noop$", "-format", "json"}, tc.args...)
			var out, stderr bytes.Buffer
			code := run(context.Background(), args, &out, &stderr, func(name string) (string, bool) {
				value, present := tc.env[name]
				return value, present
			})
			var report imaptest.Report
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatalf("invalid JSON: %v\n%s\n%s", err, &out, &stderr)
			}
			if code != 0 || report.Passed != 1 || report.Clients != 4 {
				t.Fatalf("seeded defaults or override failed: exit=%d report=%+v stderr=%s", code, report, &stderr)
			}
		})
	}
}

func TestCLIReportsRequestedClientCount(t *testing.T) {
	addr := cliEndpoint(t, false)
	var out, stderr bytes.Buffer
	args := []string{"-addr", addr, "-tls", "none", "-user", "tester", "-run", "^core/capability-noop$", "-clients", "3", "-format", "json"}
	code := run(context.Background(), args, &out, &stderr, func(string) (string, bool) { return "private-password", true })
	var report imaptest.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if code != 0 || report.Clients != 3 || report.Passed != 1 {
		t.Fatalf("clients setting lost: exit=%d report=%+v stderr=%s", code, report, &stderr)
	}
}

// cliEndpoint is a minimal network peer for command/report integration. It has
// no dependency on Sora's protocol parser or services.
func cliEndpoint(t *testing.T, refuseNOOP bool, wantLogin ...string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(connections, conn); mu.Unlock() }()
				fmt.Fprint(conn, "* OK endpoint\r\n")
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					tag, command, _ := strings.Cut(strings.TrimSpace(line), " ")
					status := "OK"
					if len(wantLogin) > 0 && strings.HasPrefix(command, "LOGIN ") && command != wantLogin[0] {
						status = "NO"
					}
					if command == "CAPABILITY" {
						fmt.Fprint(conn, "* CAPABILITY IMAP4rev1\r\n")
					}
					if command == "NOOP" && refuseNOOP {
						status = "NO"
					}
					fmt.Fprintf(conn, "%s %s complete\r\n", tag, status)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		for conn := range connections {
			conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return listener.Addr().String()
}

func TestCLIReportsPassAndAssertionFailureOverTCP(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			addr := cliEndpoint(t, fail)
			var out, stderr bytes.Buffer
			code := run(context.Background(), []string{"-addr", addr, "-tls", "none", "-user", "tester", "-run", "^core/capability-noop$", "-format", "json"}, &out, &stderr, func(name string) (string, bool) { return "private-password", name == "SORA_IMAPTEST_PASSWORD" })
			var report imaptest.Report
			if err := json.Unmarshal(out.Bytes(), &report); err != nil {
				t.Fatalf("invalid JSON: %v\n%s\n%s", err, &out, &stderr)
			}
			want := 0
			if fail {
				want = 1
			}
			if code != want || len(report.Results) != 1 {
				t.Fatalf("exit=%d report=%+v stderr=%s", code, report, &stderr)
			}
			if strings.Contains(out.String()+stderr.String(), "private-password") {
				t.Fatal("password in report")
			}
		})
	}
}

func TestCLIReadsPasswordFileAndWritesPrivateTrace(t *testing.T) {
	addr := cliEndpoint(t, false, `LOGIN "tester" "file-password"`)
	passwordFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordFile, []byte("file-password\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	trace := filepath.Join(t.TempDir(), "protocol.log")
	var out, stderr bytes.Buffer
	args := []string{"-addr", addr, "-tls", "none", "-user", "tester", "-password-file", passwordFile, "-rawlog", trace, "-run", "^core/capability-noop$"}
	if code := run(context.Background(), args, &out, &stderr, func(string) (string, bool) { return "unused-env-password", true }); code != 0 {
		t.Fatalf("exit %d: %s%s", code, &out, &stderr)
	}
	data, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("NOOP")) || bytes.Contains(data, []byte("file-password")) || bytes.Contains(data, []byte("LOGIN")) {
		t.Fatalf("invalid/redaction-unsafe trace: %s", data)
	}
	info, err := os.Stat(trace)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("trace permissions = %o", info.Mode().Perm())
	}
	out.Reset()
	stderr.Reset()
	if code := run(context.Background(), args, &out, &stderr, noPassword); code != 2 {
		t.Fatalf("existing trace overwritten: exit %d", code)
	}
}

func TestCLIInfrastructureFailureProducesJSON(t *testing.T) {
	addr := cliEndpoint(t, false)
	var out, stderr bytes.Buffer
	args := []string{"-addr", addr, "-tls", "none", "-user", "tester", "-run", "^core/capability-noop$", "-require-cap", "MOVE", "-format", "json"}
	code := run(context.Background(), args, &out, &stderr, func(string) (string, bool) { return "password", true })
	var report imaptest.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if code != 2 || !strings.Contains(report.Error, "MOVE") {
		t.Fatalf("missing infrastructure error: code=%d report=%+v", code, report)
	}
}

type failingReportWriter struct{}

func (failingReportWriter) Write([]byte) (int, error) {
	return 0, errors.New("report destination unavailable")
}

func TestCLIReportWriteFailureCannotPass(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		var stderr bytes.Buffer
		if code := run(context.Background(), []string{"-list", "-format", format}, failingReportWriter{}, &stderr, noPassword); code != 2 {
			t.Errorf("%s report write failure returned %d, want 2", format, code)
		}
	}
}
