package db_test

import (
	"context"
	"strconv"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/testutils"
)

// credentialsWithReservedCharacters are logins a hand-built "user:password@" URL cannot
// carry: most make it unparseable, "a%41b" parses to a different password.
var credentialsWithReservedCharacters = []struct{ user, password string }{
	{"sora", "pa ss"}, {"sora", "p[ss"}, {"sora", "p^ss"}, {"sora", `p\ss`},
	{"sora", "p#ss"}, {"sora", "p?ss"}, {"sora", "p/ss"}, {"sora", "p@ss:w"},
	{"sora", "50%off"}, {"sora", "a%41b"}, {"sora user", "secret"},
}

// Every pool sora and sora-admin open is built by NewDatabaseFromConfig. The server must
// receive the configured user and password verbatim, whatever characters they contain.
func TestNewDatabaseFromConfig_SendsCredentialsVerbatim(t *testing.T) {
	fake := testutils.StartFakePostgres(t)

	for _, c := range credentialsWithReservedCharacters {
		t.Run(c.user+"/"+c.password, func(t *testing.T) {
			cfg := &config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
				Hosts:    []string{fake.Host},
				Port:     int64(fake.Port), // TOML decodes an integer port as int64
				User:     c.user,
				Password: c.password,
				Name:     "sora_mail_db",
			}}
			database, err := db.NewDatabaseFromConfig(context.Background(), cfg, false)
			if err == nil {
				database.Close()
				t.Fatal("the fake server refuses every login, NewDatabaseFromConfig must fail")
			}
			login := fake.NextLogin(t, err)
			if login.User != c.user || login.Password != c.password || login.Database != "sora_mail_db" {
				t.Fatalf("server received user=%q password=%q database=%q, want %q %q %q",
					login.User, login.Password, login.Database, c.user, c.password, "sora_mail_db")
			}
		})
	}
}

// A host entry may carry its own port; it is used as is, also when the endpoint's port
// is set or unset.
func TestNewDatabaseFromConfig_HostEntryPort(t *testing.T) {
	fake := testutils.StartFakePostgres(t)

	for name, port := range map[string]any{
		"port unset":       nil,
		"other port set":   int64(5432),
		"string port set":  "5432",
		"port in host too": strconv.Itoa(fake.Port),
	} {
		t.Run(name, func(t *testing.T) {
			cfg := &config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
				Hosts:    []string{fake.Addr},
				Port:     port,
				User:     "sora",
				Password: "secret",
				Name:     "sora_mail_db",
			}}
			database, err := db.NewDatabaseFromConfig(context.Background(), cfg, false)
			if err == nil {
				database.Close()
				t.Fatal("the fake server refuses every login, NewDatabaseFromConfig must fail")
			}
			if login := fake.NextLogin(t, err); login.Password != "secret" {
				t.Fatalf("server received password %q, want %q", login.Password, "secret")
			}
		})
	}
}

// EndpointURL resolves host entries the way the server always has (a port in the entry
// wins, then the endpoint's port, then 5432) and brackets IPv6 literals.
func TestEndpointURL_HostPort(t *testing.T) {
	for _, tc := range []struct {
		host string
		port any
		want string
	}{
		{"db.example.com", nil, "db.example.com:5432"},
		{"db.example.com", int64(5433), "db.example.com:5433"},
		{"db.example.com", "5433", "db.example.com:5433"},
		{"db.example.com", 5433, "db.example.com:5433"},
		{"db.example.com:6432", int64(5433), "db.example.com:6432"},
		{"2001:db8::1", nil, "[2001:db8::1]:5432"},
		{"[2001:db8::1]", int64(5433), "[2001:db8::1]:5433"},
		{"[2001:db8::1]:6432", nil, "[2001:db8::1]:6432"},
	} {
		u, err := db.EndpointURL(&config.DatabaseEndpointConfig{Port: tc.port, Name: "sora_mail_db"}, tc.host)
		if err != nil {
			t.Fatalf("host %q port %v: %v", tc.host, tc.port, err)
		}
		if u.Host != tc.want {
			t.Errorf("host %q port %v: got %q, want %q", tc.host, tc.port, u.Host, tc.want)
		}
	}
	for _, port := range []any{"x", int64(0), int64(70000), 1.5} {
		if _, err := db.EndpointURL(&config.DatabaseEndpointConfig{Port: port}, "db.example.com"); err == nil {
			t.Errorf("port %v: expected an error", port)
		}
	}
}
