package main

import (
	"strings"
	"testing"

	"github.com/migadu/sora/config"
)

// recordingReloader stands in for a running server: it keeps every config its
// ReloadConfig was handed.
type recordingReloader struct {
	reloaded []config.ServerConfig
}

func (r *recordingReloader) ReloadConfig(cfg config.ServerConfig) error {
	r.reloaded = append(r.reloaded, cfg)
	return nil
}

// runningDeps is a node that started the given servers, each registered for reload.
func runningDeps(t *testing.T, servers ...config.ServerConfig) (*serverDependencies, map[string]*recordingReloader) {
	t.Helper()
	deps := &serverDependencies{config: config.NewDefaultConfig()}
	deps.config.DynamicServers = servers
	reloaders := make(map[string]*recordingReloader, len(servers))
	for _, s := range servers {
		r := &recordingReloader{}
		deps.registerServer(s.Name, r)
		reloaders[s.Name] = r
	}
	return deps, reloaders
}

func reloadedConfig(servers ...config.ServerConfig) *config.Config {
	cfg := config.NewDefaultConfig()
	cfg.DynamicServers = servers
	return &cfg
}

// The User API's ReloadConfig applies jwt_secret, allowed_origins and allowed_hosts and
// nothing else. A reload that changes addr and token_duration must say they need a
// restart, naming them, as the global report does for [cleanup] and the like, and must
// not name allowed_origins, which it did apply. The server still gets the new config.
func TestServerReloadReportsRestartOnlySettings(t *testing.T) {
	logs := captureReloadLogs(t)
	deps, reloaders := runningDeps(t, config.ServerConfig{
		Type: "http_user_api", Name: "user-api", Addr: ":8081",
		TokenDuration: "24h", AllowedOrigins: []string{"https://mail.example.com"},
	})

	next := config.ServerConfig{
		Type: "http_user_api", Name: "user-api", Addr: ":9091",
		TokenDuration: "48h", AllowedOrigins: []string{"https://webmail.example.com"},
	}
	deps.reloadServers(reloadedConfig(next))

	if got := reloaders["user-api"].reloaded; len(got) != 1 || got[0].TokenDuration != "48h" {
		t.Fatalf("ReloadConfig got %+v, want the new config once", got)
	}
	out := logs.String()
	if !hasLineWith(out, `server=user-api`, "require restart", "addr", "token_duration") {
		t.Errorf("no restart notice naming addr and token_duration for user-api:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "require restart") && strings.Contains(line, "allowed_origins") {
			t.Errorf("allowed_origins, which ReloadConfig applies, reported as needing a restart:\n%s", line)
		}
	}
}

// A reload that changes only settings ReloadConfig applies has nothing to report.
func TestServerReloadSaysNothingWhenEverythingChangedWasApplied(t *testing.T) {
	logs := captureReloadLogs(t)
	deps, _ := runningDeps(t, config.ServerConfig{
		Type: "http_user_api", Name: "user-api", Addr: ":8081", AllowedOrigins: []string{"https://mail.example.com"},
	})

	deps.reloadServers(reloadedConfig(config.ServerConfig{
		Type: "http_user_api", Name: "user-api", Addr: ":8081", AllowedOrigins: []string{"https://webmail.example.com"},
	}))

	if out := logs.String(); strings.Contains(out, "require restart") {
		t.Errorf("a reload that changed only applied settings reported a restart:\n%s", out)
	}
}
