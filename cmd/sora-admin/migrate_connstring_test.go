package main

import (
	"context"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/testutils"
)

// sora-admin migrate must reach the same server, with the same credentials, as the
// server does for the same [database.write] section: escaped user and password, the
// default port when none is set, and a port already in the host entry kept.
func TestMigrateConnection_UsesServerConnectionRules(t *testing.T) {
	fake := testutils.StartFakePostgres(t)

	cases := []struct {
		name string
		host string
		port any
		pass string
	}{
		{name: "reserved characters in password", host: fake.Host, port: int64(fake.Port), pass: "p#ss?/50%off a%41b"},
		{name: "port unset, port in host entry", host: fake.Addr, port: nil, pass: "secret"},
		{name: "port set, port in host entry", host: fake.Addr, port: int64(5432), pass: "secret"},
	}
	saved := globalConfig.Database.Write
	t.Cleanup(func() { globalConfig.Database.Write = saved })

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			globalConfig.Database.Write = &config.DatabaseEndpointConfig{
				Hosts:    []string{tc.host},
				Port:     tc.port,
				User:     "sora",
				Password: tc.pass,
				Name:     "sora_mail_db",
			}
			m, sqlDB, err := getMigrateInstance(context.Background())
			if err == nil {
				m.Close()
				sqlDB.Close()
				t.Fatal("the fake server refuses every login, getMigrateInstance must fail")
			}
			login := fake.NextLogin(t, err)
			if login.User != "sora" || login.Password != tc.pass || login.Database != "sora_mail_db" {
				t.Fatalf("server received user=%q password=%q database=%q, want %q %q %q",
					login.User, login.Password, login.Database, "sora", tc.pass, "sora_mail_db")
			}
		})
	}
}
