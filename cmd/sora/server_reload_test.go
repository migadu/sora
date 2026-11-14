package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

// A block that lost its addr in an edit is invalid: the reload says so, instead of
// passing over the block in silence, and the server keeps the config it has.
func TestServerReloadRejectsBlockWithoutAddr(t *testing.T) {
	logs := captureReloadLogs(t)
	deps, reloaders := runningDeps(t, config.ServerConfig{Type: "pop3", Name: "pop3", Addr: ":110"})

	deps.reloadServers(reloadedConfig(config.ServerConfig{Type: "pop3", Name: "pop3"}))

	if got := reloaders["pop3"].reloaded; len(got) != 0 {
		t.Fatalf("ReloadConfig got %+v, want no call", got)
	}
	if out := logs.String(); !hasLineWith(out, "Skipping reload", "server=pop3", "server address is required") {
		t.Errorf("no error naming pop3 and its missing addr:\n%s", out)
	}
}

// Every setting in the table is one RestartRequiredChanges can name (a table name such
// as "timeouts" would match nothing and so silence nothing), under a real server type.
func TestReloadableServerSettingsAreRealKeys(t *testing.T) {
	keys := config.ServerConfigKeys()
	for typ, settings := range reloadableServerSettings {
		probe := config.ServerConfig{Type: typ, Name: typ, Addr: ":1"}
		if err := probe.Validate(); err != nil {
			t.Errorf("%q is not a server type: %v", typ, err)
		}
		for _, setting := range settings {
			if !slices.Contains(keys, setting) {
				t.Errorf("%s: %q is not a setting of [[server]]", typ, setting)
			}
		}
	}
}

// reloadConfigSources is where each type's ReloadConfig lives. These are the types
// main.go registers for reload: every type but metrics, which has no ReloadConfig.
var reloadConfigSources = map[string]string{
	"imap":              "server/imap/server.go",
	"pop3":              "server/pop3/server.go",
	"managesieve":       "server/managesieve/server.go",
	"lmtp":              "server/lmtp/server.go",
	"imap_proxy":        "server/imapproxy/server.go",
	"pop3_proxy":        "server/pop3proxy/server.go",
	"managesieve_proxy": "server/managesieveproxy/server.go",
	"lmtp_proxy":        "server/lmtpproxy/server.go",
	"http_admin_api":    "server/adminapi/server.go",
	"http_user_api":     "server/userapi/server.go",
	"user_api_proxy":    "server/userapiproxy/server.go",
}

// reloadedSettingKeys maps the names a ReloadConfig appends to "reloaded" to their TOML
// keys where the two differ: the timeouts and limits live in tables.
var reloadedSettingKeys = map[string]string{
	"command_timeout":          "timeouts.command_timeout",
	"absolute_session_timeout": "timeouts.absolute_session_timeout",
	"min_bytes_per_minute":     "timeouts.min_bytes_per_minute",
	"session_memory_limit":     "limits.session_memory_limit",
	"max_auth_errors":          "limits.max_auth_errors",
}

// Each list in reloadableServerSettings must be exactly what its ReloadConfig applies,
// read off the names it appends to "reloaded" (each a string literal). A setting
// applied but not listed would be reported as needing a restart it does not need; one
// listed but no longer applied would go unreported. Every type that registers for
// reload has an entry, since a type without one has every change reported.
func TestReloadableServerSettingsMatchEachReloadConfig(t *testing.T) {
	appended := regexp.MustCompile(`reloaded = append\(reloaded, "([a-z_]+)"\)`)
	for typ, path := range reloadConfigSources {
		src, err := os.ReadFile(filepath.Join("..", "..", path))
		if err != nil {
			t.Fatal(err)
		}
		var applies []string
		for _, m := range appended.FindAllStringSubmatch(string(src), -1) {
			key := m[1]
			if tableKey, ok := reloadedSettingKeys[key]; ok {
				key = tableKey
			}
			applies = append(applies, key)
		}
		if len(applies) == 0 {
			t.Errorf("%s: no `reloaded = append(reloaded, \"...\")` found; has ReloadConfig changed shape?", path)
			continue
		}
		slices.Sort(applies)
		applies = slices.Compact(applies)

		listed, ok := reloadableServerSettings[typ]
		if !ok {
			t.Errorf("no reloadable settings for %q, which registers for reload", typ)
			continue
		}
		listed = slices.Sorted(slices.Values(listed))
		if !slices.Equal(listed, applies) {
			t.Errorf("%s: the table lists %v, ReloadConfig in %s applies %v", typ, listed, path, applies)
		}
	}
	for typ := range reloadableServerSettings {
		if _, ok := reloadConfigSources[typ]; !ok {
			t.Errorf("%q is in the table but has no ReloadConfig source listed here", typ)
		}
	}
}

func TestServerReloadReportsDebugRequiresRestart(t *testing.T) {
	for _, typ := range []string{"lmtp", "lmtp_proxy", "imap_proxy"} {
		t.Run(typ, func(t *testing.T) {
			logs := captureReloadLogs(t)
			started := config.ServerConfig{Type: typ, Name: typ, Addr: ":1234"}
			deps, _ := runningDeps(t, started)
			next := started
			next.Debug = true
			deps.reloadServers(reloadedConfig(next))
			if !hasLineWith(logs.String(), "server="+typ, "require restart", "debug") {
				t.Errorf("missing debug restart notice: %s", logs.String())
			}
		})
	}
}
