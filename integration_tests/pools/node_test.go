//go:build integration

package pools_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/userapi"
	"golang.org/x/crypto/bcrypt"
)

const nodeJWTSecret = "pools-node-test-jwt-secret-0123456789abcdef"

// TestSoraNodeRoutesByPoolsFromConfigFile starts the real sora binary from a configuration
// file with [[pool]] blocks and every proxy type, and checks from the outside that each
// proxy routes by the pool the lookup names. The live pools' IMAP, POP3, ManageSieve and
// LMTP backends REQUIRE the PROXY protocol, which only the pool block switches on, so a
// successful login also proves the pool's settings reached the proxy through the file.
//
// Expected behaviour:
//   - a user whose answer names a live pool logs in / delivers / calls the API on every proxy;
//   - a user whose pool's only member is dead is refused with a temporary failure everywhere,
//     although live backends are one hash away;
//   - the node runs proxy-only: no database, no object storage.
func TestSoraNodeRoutesByPoolsFromConfigFile(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	bin := common.GetSoraBinary(t)

	imapBackend, _ := common.SetupIMAPServerWithPROXY(t)
	defer imapBackend.Close()
	pop3Backend, _ := common.SetupPOP3ServerWithPROXY(t)
	defer pop3Backend.Close()
	sieveBackend, _ := common.SetupManageSieveServerWithPROXY(t)
	defer sieveBackend.Close()
	lmtpBackend, _ := common.SetupLMTPServerWithPROXY(t)
	defer lmtpBackend.Close()
	rdb := imapBackend.ResilientDB

	api, err := userapi.New(rdb, userapi.ServerOptions{
		Name: "api-backend", Addr: "127.0.0.1:0", JWTSecret: nodeJWTSecret, TokenDuration: time.Hour,
		TokenIssuer: "test-issuer", AllowedOrigins: []string{"*"}, AllowedHosts: []string{"127.0.0.1", "localhost"},
	})
	if err != nil {
		t.Fatalf("userapi.New: %v", err)
	}
	apiBackend := httptest.NewServer(api.SetupRoutes())
	defer apiBackend.Close()

	stamp := time.Now().UnixNano()
	live := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("node-live-%d@example.com", stamp), "pw-live")
	dead := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("node-dead-%d@example.com", stamp), "pw-dead")
	hash := func(pw string) string {
		h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		return string(h)
	}
	// One pool per protocol for the live user: every test backend sits on 127.0.0.1 with
	// its own port, so a pool cannot be "a host, any port" as in production.
	answers := map[string]map[string]any{
		live.Email: {"address": live.Email, "password_hash": hash(live.Password)},
		dead.Email: {"address": dead.Email, "password_hash": hash(dead.Password), "pool": "dead"},
	}
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		answer, ok := answers[email]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		out := map[string]any{}
		for k, v := range answer {
			out[k] = v
		}
		if email == live.Email {
			// The live user's pool depends on the proxy asking (the test backends are one
			// pool per protocol); the proxy identifies itself by the port it asks for.
			out["pool"] = r.URL.Query().Get("proto")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer lookup.Close()

	imapAddr := common.GetRandomAddress(t)
	pop3Addr := common.GetRandomAddress(t)
	sieveAddr := common.GetRandomAddress(t)
	lmtpAddr := common.GetRandomAddress(t)
	apiAddr := common.GetRandomAddress(t)

	lookupURL := func(proto string) string {
		return lookup.URL + "/lookup?proto=" + proto + "&email=$email"
	}
	cfg := fmt.Sprintf(`
[logging]
output = "stdout"
format = "console"
level = "info"

[servers]
trusted_networks = ["127.0.0.0/8", "::1/128"]

[[pool]]
name = "imap"
backends = [%q]
remote_use_proxy_protocol = true

[[pool]]
name = "pop3"
backends = [%q]
remote_use_proxy_protocol = true

[[pool]]
name = "sieve"
backends = [%q]
remote_use_proxy_protocol = true

[[pool]]
name = "lmtp"
backends = [%q]
remote_use_proxy_protocol = true

[[pool]]
name = "api"
backends = [%q]

[[pool]]
name = "dead"
backends = ["127.0.0.1:1"]
remote_use_proxy_protocol = true

[[server]]
type = "imap_proxy"
name = "imap-proxy"
addr = %q
remote_port = 143
master_sasl_username = "proxyuser"
master_sasl_password = "proxypass"
[server.remote_lookup]
enabled = true
url = %q
timeout = "5s"
[server.auth_rate_limit]
enabled = false

[[server]]
type = "pop3_proxy"
name = "pop3-proxy"
addr = %q
remote_port = 110
master_sasl_username = "proxyuser"
master_sasl_password = "proxypass"
[server.remote_lookup]
enabled = true
url = %q
timeout = "5s"
[server.auth_rate_limit]
enabled = false

[[server]]
type = "managesieve_proxy"
name = "sieve-proxy"
addr = %q
remote_port = 4190
insecure_auth = true
master_sasl_username = "master_sasl"
master_sasl_password = "master_sasl_secret"
[server.remote_lookup]
enabled = true
url = %q
timeout = "5s"
[server.auth_rate_limit]
enabled = false

[[server]]
type = "lmtp_proxy"
name = "lmtp-proxy"
addr = %q
remote_port = 24
[server.remote_lookup]
enabled = true
url = %q
timeout = "5s"

[[server]]
type = "user_api_proxy"
name = "api-proxy"
addr = %q
remote_port = 8081
jwt_secret = %q
[server.remote_lookup]
enabled = true
url = %q
timeout = "5s"
`,
		imapBackend.Address, pop3Backend.Address, sieveBackend.Address, lmtpBackend.Address, apiBackend.Listener.Addr().String(),
		imapAddr, lookupURL("imap"),
		pop3Addr, lookupURL("pop3"),
		sieveAddr, lookupURL("sieve"),
		lmtpAddr, lookupURL("lmtp"),
		apiAddr, nodeJWTSecret, lookupURL("api"),
	)
	cfgPath := filepath.Join(t.TempDir(), "sora.toml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	node := startNode(t, bin, cfgPath, imapAddr, pop3Addr, sieveAddr, lmtpAddr, apiAddr)
	defer node.stop()

	t.Run("IMAP", func(t *testing.T) {
		if err := imapLogin(t, imapAddr, live); err != nil {
			t.Fatalf("live user: %v", err)
		}
		err := imapLogin(t, imapAddr, dead)
		var ie *imap.Error
		if err == nil || !errors.As(err, &ie) || ie.Code != imap.ResponseCodeUnavailable {
			t.Fatalf("dead pool: err = %v, want NO [UNAVAILABLE]", err)
		}
	})
	t.Run("POP3", func(t *testing.T) {
		if resp := pop3Login(t, pop3Addr, live); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("live user: %s", resp)
		}
		if resp := pop3Login(t, pop3Addr, dead); strings.HasPrefix(resp, "+OK") || !strings.Contains(resp, "SYS/TEMP") {
			t.Fatalf("dead pool: %s, want -ERR [SYS/TEMP]", resp)
		}
	})
	t.Run("ManageSieve", func(t *testing.T) {
		if resp := sieveAuth(t, sieveAddr, live); !strings.HasPrefix(resp, "OK") {
			t.Fatalf("live user: %s", resp)
		}
		if resp := sieveAuth(t, sieveAddr, dead); !strings.HasPrefix(resp, "NO") {
			t.Fatalf("dead pool: %s, want NO", resp)
		}
	})
	t.Run("LMTP", func(t *testing.T) {
		if resp := lmtpRcpt(t, lmtpAddr, live.Email); !strings.HasPrefix(resp, "250") {
			t.Fatalf("live user: %s", resp)
		}
		if resp := lmtpRcpt(t, lmtpAddr, dead.Email); !strings.HasPrefix(resp, "451") {
			t.Fatalf("dead pool: %s, want 451", resp)
		}
	})
	t.Run("UserAPI", func(t *testing.T) {
		if status := apiLogin(t, apiAddr, live); status != http.StatusOK {
			t.Fatalf("live user: %d", status)
		}
		// A temporary failure: 502 when the pool's backend cannot be reached, 503 when there
		// is no pool to route into. Never a 2xx (routed elsewhere) or a 401 (wrong password).
		if status := apiLogin(t, apiAddr, dead); status != http.StatusBadGateway && status != http.StatusServiceUnavailable {
			t.Fatalf("dead pool: %d, want 502 or 503", status)
		}
	})
}

type soraNode struct {
	t    *testing.T
	cmd  *exec.Cmd
	out  *bytes.Buffer
	done chan error
}

// startNode runs the sora binary on cfgPath and waits until every listener accepts.
func startNode(t *testing.T, bin, cfgPath string, listeners ...string) *soraNode {
	t.Helper()
	cmd := exec.Command(bin, "-config", cfgPath)
	out := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sora: %v", err)
	}
	node := &soraNode{t: t, cmd: cmd, out: out, done: make(chan error, 1)}
	go func() { node.done <- cmd.Wait() }()

	deadline := time.Now().Add(30 * time.Second)
	for _, addr := range listeners {
		for {
			select {
			case err := <-node.done:
				t.Fatalf("sora exited before listening on %s: %v\n--- output ---\n%s", addr, err, out.String())
			default:
			}
			conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
			if err == nil {
				conn.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("sora did not listen on %s within 30s\n--- output ---\n%s", addr, out.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	return node
}

func (n *soraNode) stop() {
	_ = n.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-n.done:
	case <-time.After(10 * time.Second):
		_ = n.cmd.Process.Kill()
		<-n.done
	}
	if n.t.Failed() {
		n.t.Logf("--- sora output ---\n%s", n.out.String())
	}
}

func imapLogin(t *testing.T, addr string, account common.TestAccount) error {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer c.Close()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		return err
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		return err
	}
	return c.Logout().Wait()
}

func lineClient(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	return conn, bufio.NewReader(conn)
}

func readLine(t *testing.T, r *bufio.Reader, what string) string {
	t.Helper()
	line, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("read %s: %v", what, err)
	}
	return strings.TrimSpace(line)
}

func pop3Login(t *testing.T, addr string, account common.TestAccount) string {
	t.Helper()
	conn, r := lineClient(t, addr)
	defer conn.Close()
	readLine(t, r, "greeting")
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	readLine(t, r, "USER")
	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	return readLine(t, r, "PASS")
}

func sieveAuth(t *testing.T, addr string, account common.TestAccount) string {
	t.Helper()
	conn, r := lineClient(t, addr)
	defer conn.Close()
	for {
		line := readLine(t, r, "greeting")
		if strings.HasPrefix(line, "OK") {
			break
		}
	}
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)))
	fmt.Fprintf(conn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", auth)
	return readLine(t, r, "AUTHENTICATE")
}

func lmtpRcpt(t *testing.T, addr, rcpt string) string {
	t.Helper()
	conn, r := lineClient(t, addr)
	defer conn.Close()
	readLine(t, r, "greeting")
	fmt.Fprintf(conn, "LHLO client.example\r\n")
	for {
		line := readLine(t, r, "LHLO")
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}
	fmt.Fprintf(conn, "MAIL FROM:<sender@example.com>\r\n")
	if resp := readLine(t, r, "MAIL FROM"); !strings.HasPrefix(resp, "250") {
		t.Fatalf("MAIL FROM: %s", resp)
	}
	fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", rcpt)
	return readLine(t, r, "RCPT TO")
}

func apiLogin(t *testing.T, addr string, account common.TestAccount) int {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": account.Email, "password": account.Password})
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Post("http://"+addr+"/user/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
