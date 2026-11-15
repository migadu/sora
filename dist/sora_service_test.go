package dist

import (
	"bufio"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/tlsmanager"
)

// systemdUnit holds the settings of a unit file: section -> key -> every value given,
// in order (systemd accumulates list settings such as ReadWritePaths= across lines).
type systemdUnit map[string]map[string][]string

func parseSystemdUnit(t *testing.T, file string) systemdUnit {
	t.Helper()
	f, err := os.Open(file)
	if err != nil {
		t.Fatalf("open %s: %v", file, err)
	}
	defer f.Close()

	unit := systemdUnit{}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "", strings.HasPrefix(line, "#"), strings.HasPrefix(line, ";"):
			continue
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = line[1 : len(line)-1]
			if unit[section] == nil {
				unit[section] = map[string][]string{}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			t.Fatalf("%s: unparseable line %q", file, line)
		}
		unit[section][strings.TrimSpace(key)] = append(unit[section][strings.TrimSpace(key)], strings.TrimSpace(value))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	return unit
}

// words returns every whitespace-separated word of every value of section.key.
func (u systemdUnit) words(section, key string) []string {
	var out []string
	for _, v := range u[section][key] {
		out = append(out, strings.Fields(v)...)
	}
	return out
}

// persistentWritableRoots are the directories the service may write under
// ProtectSystem=strict and that survive a stop: ReadWritePaths= and the directories
// systemd creates for StateDirectory=, CacheDirectory= and LogsDirectory= (systemd.exec(5),
// "Automatic directory creation"). PrivateTmp's /tmp and /var/tmp are writable too but
// are removed when the service stops, and RuntimeDirectory= is removed likewise, so
// neither counts.
func (u systemdUnit) persistentWritableRoots() []string {
	var roots []string
	for _, p := range u.words("Service", "ReadWritePaths") {
		roots = append(roots, strings.TrimPrefix(p, "-"))
	}
	for _, dir := range []struct{ key, base string }{
		{"StateDirectory", "/var/lib"},
		{"CacheDirectory", "/var/cache"},
		{"LogsDirectory", "/var/log"},
	} {
		for _, d := range u.words("Service", dir.key) {
			// "name[:symlink]": only the directory itself is writable.
			name, _, _ := strings.Cut(d, ":")
			roots = append(roots, path.Join(dir.base, name))
		}
	}
	return roots
}

func under(p, root string) bool {
	p, root = path.Clean(p), path.Clean(root)
	return p == root || strings.HasPrefix(p, root+"/")
}

// TestSystemdUnitDoesNotRequirePostgreSQL: a proxy node, or a backend whose database is
// on another host, has no postgresql.service, and Requires= on a unit that does not exist
// fails the start job. Requires= (and BindsTo=/Requisite=) also stop sora whenever the
// database unit is stopped or restarted (systemd.unit(5)).
func TestSystemdUnitDoesNotRequirePostgreSQL(t *testing.T) {
	unit := parseSystemdUnit(t, "sora.service")
	for _, key := range []string{"Requires", "Requisite", "BindsTo"} {
		for _, dep := range unit.words("Unit", key) {
			if strings.HasPrefix(dep, "postgresql") {
				t.Errorf("[Unit] %s=%s: sora must start on hosts without a local PostgreSQL unit and must not stop when it does", key, dep)
			}
		}
	}
}

// soraWritableDirs lists every directory sora writes by default, or with the paths
// config.toml.example suggests.
func soraWritableDirs(t *testing.T) []struct{ what, dir string } {
	t.Helper()
	defaults := config.NewDefaultConfig()
	var example config.Config
	if err := config.LoadConfigFromFile(filepath.Join("..", "config.toml.example"), &example); err != nil {
		t.Fatalf("load config.toml.example: %v", err)
	}
	return []struct{ what, dir string }{
		{"default [uploader] path", defaults.Uploader.Path},
		{"default [local_cache] path", defaults.LocalCache.Path},
		{"default [auth_cache] path", path.Dir(defaults.AuthCache.Path)},
		{"default [relay.queue] path", defaults.Relay.GetQueuePath()},
		{"default TLS fallback_dir", tlsmanager.DefaultFallbackDir},
		{"config.toml.example [uploader] path", example.Uploader.Path},
		{"config.toml.example [local_cache] path", example.LocalCache.Path},
		{"config.toml.example [auth_cache] path", path.Dir(example.AuthCache.Path)},
		{"config.toml.example [relay.queue] path", example.Relay.GetQueuePath()},
	}
}

// TestSystemdUnitKeepsSoraPathsWritableAndPersistent: every directory sora writes by
// default, or with the paths config.toml.example suggests, must be writable under the
// unit's ProtectSystem=strict and must survive a restart. The uploader directory holds
// the only copy of a message body until it reaches S3; the TLS fallback directory is
// what handshakes use while S3 is down; the caches exist to survive restarts.
func TestSystemdUnitKeepsSoraPathsWritableAndPersistent(t *testing.T) {
	unit := parseSystemdUnit(t, "sora.service")
	if got := unit["Service"]["ProtectSystem"]; len(got) == 0 || got[len(got)-1] != "strict" {
		t.Fatalf("ProtectSystem = %v; this test assumes \"strict\" (only listed paths writable)", got)
	}
	roots := unit.persistentWritableRoots()

	for _, d := range soraWritableDirs(t) {
		if d.dir == "" || d.dir == "." {
			t.Errorf("%s is not set", d.what)
			continue
		}
		ok := false
		for _, root := range roots {
			if under(d.dir, root) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("%s %q is not under a persistent writable directory of the unit %v (PrivateTmp=%v)",
				d.what, d.dir, roots, unit["Service"]["PrivateTmp"])
		}
	}
}

// TestSystemdUnitKeepsSoraDirectoriesPrivate: at every start systemd gives each
// StateDirectory=, CacheDirectory= and LogsDirectory= directory the access mode of its
// *DirectoryMode= setting, 0755 when unset, whatever an administrator set (systemd.exec(5),
// "Automatic directory creation"). The local cache keeps message bodies in 0644 files and
// the log file is 0644: under a directory open to others every local account can read
// them. With the earlier /tmp defaults they sat in the unit's private /tmp.
func TestSystemdUnitKeepsSoraDirectoriesPrivate(t *testing.T) {
	unit := parseSystemdUnit(t, "sora.service")
	for _, key := range []string{"StateDirectory", "CacheDirectory", "LogsDirectory"} {
		if len(unit.words("Service", key)) == 0 {
			continue
		}
		mode := "0755"
		if got := unit["Service"][key+"Mode"]; len(got) > 0 {
			mode = got[len(got)-1]
		}
		m, err := strconv.ParseUint(mode, 8, 32)
		if err != nil {
			t.Fatalf("%sMode=%s: %v", key, mode, err)
		}
		if m&0o007 != 0 {
			t.Errorf("%s= directories get mode %s, open to every local account; set %sMode=0750", key, mode, key)
		}
	}
}

// TestRCScriptCreatesSoraDirectories: the FreeBSD script runs sora as an unprivileged
// user, which cannot create a directory under /var. Every directory sora writes by default
// must be under one the start precmd creates for that user, or sora cannot start: the
// local cache and the uploader directory are fatal at start-up.
func TestRCScriptCreatesSoraDirectories(t *testing.T) {
	script, err := os.ReadFile("sora.rc")
	if err != nil {
		t.Fatal(err)
	}
	// : ${sora_spooldir:="/var/spool/sora"}
	defaults := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^: \$\{(sora_\w+):="([^"]*)"\}`).FindAllStringSubmatch(string(script), -1) {
		defaults[m[1]] = m[2]
	}
	// install -d -o ${sora_user} -g ${sora_group} -m 750 ${sora_spooldir}
	var created []string
	for _, m := range regexp.MustCompile(`(?m)^\s*install -d .*\$\{(sora_\w+)\}\s*$`).FindAllStringSubmatch(string(script), -1) {
		dir, ok := defaults[m[1]]
		if !ok {
			t.Fatalf("install -d of ${%s}, which has no default", m[1])
		}
		created = append(created, dir)
	}

	for _, d := range soraWritableDirs(t) {
		ok := false
		for _, root := range created {
			if under(d.dir, root) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("%s %q is not under a directory the start precmd creates %v", d.what, d.dir, created)
		}
	}
}
