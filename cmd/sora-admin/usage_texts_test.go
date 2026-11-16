package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/sora/db"
)

// adminCommandRef is one `sora-admin <command> [<subcommand> ...] [--flag ...]` that a usage
// text, an example or a hint names.
type adminCommandRef struct {
	words []string // command, subcommand and further fixed words ("backends maintenance on")
	flags []string // flag names, without dashes
}

var adminCommandWord = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// parseAdminCommandRefs returns the sora-admin command lines in text. A mention counts when
// it starts the line or follows ":", "'", "`", "(" or "|" (so prose such as "a sora-admin
// that hashes" is not one); it ends at a closing quote or parenthesis, a shell substitution,
// or a word with trailing punctuation. A placeholder (<subcommand>, [options], PATH, %s)
// ends the command words, and when it stands where a subcommand would, the flags after it
// belong to a command not named here and are dropped.
func parseAdminCommandRefs(text string) []adminCommandRef {
	var refs []adminCommandRef
	for _, line := range strings.Split(text, "\n") {
		for rest := line; ; {
			i := strings.Index(rest, "sora-admin ")
			if i < 0 {
				break
			}
			before := strings.TrimSpace(rest[:i])
			rest = rest[i+len("sora-admin "):]
			if before != "" && !strings.ContainsAny(before[len(before)-1:], ":'`(|") {
				continue
			}
			cmdline := rest
			if j := strings.IndexAny(cmdline, "'`)$"); j >= 0 {
				cmdline = cmdline[:j]
			}
			var ref adminCommandRef
			wordsDone, placeholder := false, false
			fields := strings.Fields(cmdline)
			for k := 0; k < len(fields); k++ {
				raw := fields[k]
				tok := strings.TrimRight(strings.Trim(raw, `[]"`), ",.;")
				switch {
				case tok == "--config":
					k++ // and its value
				case strings.HasPrefix(tok, "--config="):
				case strings.HasPrefix(tok, "-") && len(tok) > 1:
					wordsDone = true
					name, _, _ := strings.Cut(strings.TrimLeft(tok, "-"), "=")
					if name != "help" && name != "h" {
						ref.flags = append(ref.flags, name)
					}
				case !wordsDone && !strings.HasPrefix(raw, "[") && adminCommandWord.MatchString(tok):
					ref.words = append(ref.words, tok)
				default:
					placeholder = placeholder || !wordsDone
					wordsDone = true
				}
				if strings.ContainsAny(raw[len(raw)-1:], ",.;") {
					break
				}
			}
			if placeholder {
				ref.flags = nil
			}
			if len(ref.words) > 0 {
				refs = append(refs, ref)
			}
		}
	}
	return refs
}

func TestParseAdminCommandRefs(t *testing.T) {
	for _, tc := range []struct {
		text string
		want []string // words, then flags after "|"
	}{
		{"  sora-admin --config config.toml accounts list --domain example.com", []string{"accounts list|domain"}},
		{"Usage: sora-admin migrate down --config config.toml [--limit N | --all]", []string{"migrate down|limit all"}},
		{"  sora-admin backends maintenance on  --host HOST [--wait]", []string{"backends maintenance on|host wait"}},
		{"  sora-admin stats blocked [options]", []string{"stats blocked|"}},
		{"Use 'sora-admin accounts <subcommand> --help' for detailed help.", []string{"accounts|"}},
		{"Hint: using: sora-admin accounts create --email %s --password <password>", []string{"accounts create|email password"}},
		{"  sora-admin messages restore --since $(date -u -d '1 day ago') --confirm", []string{"messages restore|since"}},
		{"(sora-admin relay stats, on that node)", []string{"relay stats|"}},
		{"cat script.sieve | sora-admin sieve put --name x", []string{"sieve put|name"}},
		{"import with a sora-admin that hashes with BLAKE3", nil},
		{"Use 'sora-admin --config PATH <command> --help'", nil},
	} {
		var got []string
		for _, ref := range parseAdminCommandRefs(tc.text) {
			got = append(got, strings.Join(ref.words, " ")+"|"+strings.Join(ref.flags, " "))
		}
		if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
			t.Errorf("parseAdminCommandRefs(%q) = %q, want %q", tc.text, got, tc.want)
		}
	}
}

// adminSourceStrings returns the string literals of the package's non-test files by
// position: the usage texts, examples, hints and errors sora-admin prints.
func adminSourceStrings(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := make(map[string]string)
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					out[fset.Position(lit.Pos()).String()] = s
				}
			}
			return true
		})
	}
	return out
}

// listedNames returns the first word of each line of the section under heading
// ("Commands:", "Subcommands:") of a usage text.
func listedNames(usage, heading string) []string {
	var names []string
	in := false
	for _, line := range strings.Split(usage, "\n") {
		if strings.TrimSpace(line) == heading {
			in = true
			continue
		}
		if !in {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			break
		}
		names = append(names, fields[0])
	}
	return names
}

// unreachableAdminConfig writes a config through which no database or Admin API is
// reachable, so a command that does not stop where a test expects fails instead of acting.
func unreachableAdminConfig(t *testing.T, withAdminCLI bool) string {
	t.Helper()
	content := "[database.write]\nhosts = [\"127.0.0.1:1\"]\n"
	if withAdminCLI {
		content += "[admin_cli]\naddr = \"http://127.0.0.1:1\"\napi_key = \"test-key\"\n"
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

var (
	unknownCommand   = regexp.MustCompile(`(?m)^Unknown ([a-z-]+ )?(sub)?command: .*`)
	undefinedFlag    = regexp.MustCompile(`flag provided but not defined: \S+`)
	minCommandRefs   = 100 // the package's strings name far more; fewer means the parser broke
	minListedCommand = 10
)

// TestUsageTextsNameRealCommands (#317): every command, subcommand and flag a usage text,
// example or hint tells the operator to run exists. It walks the command table (each
// command `sora-admin help` lists, each subcommand that command's usage lists) and every
// `sora-admin ...` line in the package's strings, and runs each through main with --help.
// A command main does not know answers "Unknown ... subcommand", a flag the command does
// not define "flag provided but not defined". Flags get the value 0, which every flag type
// parses, so the run stops at --help.
func TestUsageTextsNameRealCommands(t *testing.T) {
	configPath := unreachableAdminConfig(t, true)

	type check struct {
		flags map[string]bool
		where map[string]bool
	}
	checks := make(map[string]*check)
	add := func(words, flags []string, where string) {
		key := strings.Join(words, " ")
		c := checks[key]
		if c == nil {
			c = &check{flags: make(map[string]bool), where: make(map[string]bool)}
			checks[key] = c
		}
		for _, f := range flags {
			c.flags[f] = true
		}
		c.where[where] = true
	}

	top, _ := runAdminMain(t, "help")
	commands := listedNames(top, "Commands:")
	if len(commands) < minListedCommand {
		t.Fatalf("`sora-admin help` lists %d commands:\n%s", len(commands), top)
	}
	for _, cmd := range commands {
		if cmd == "help" || cmd == "version" {
			continue
		}
		add([]string{cmd}, nil, "sora-admin help")
		usage, _ := runAdminMain(t, "--config", configPath, cmd, "--help")
		for _, sub := range listedNames(usage, "Subcommands:") {
			add([]string{cmd, sub}, nil, "sora-admin "+cmd+" --help")
		}
	}

	refs := 0
	for where, s := range adminSourceStrings(t) {
		for _, ref := range parseAdminCommandRefs(s) {
			add(ref.words, ref.flags, where)
			refs++
		}
	}
	if refs < minCommandRefs {
		t.Fatalf("found %d sora-admin command lines in the package's strings", refs)
	}

	for key, c := range checks {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			args := append([]string{"--config", configPath}, strings.Fields(key)...)
			flags := make([]string, 0, len(c.flags))
			for f := range c.flags {
				flags = append(flags, f)
			}
			sort.Strings(flags)
			for _, f := range flags {
				args = append(args, "--"+f+"=0")
			}
			args = append(args, "--help")
			out, _ := runAdminMain(t, args...)
			problem := unknownCommand.FindString(out)
			if m := undefinedFlag.FindString(out); m != "" {
				problem = m
			}
			if problem != "" {
				where := make([]string, 0, len(c.where))
				for w := range c.where {
					where = append(where, w)
				}
				sort.Strings(where)
				t.Errorf("sora-admin %s: %s\n  named at %s", strings.Join(args[2:], " "), problem, strings.Join(where, ", "))
			}
		})
	}
}

// TestUsageTextsMatchTheCode (#317): usage texts and hints that name a config key, a file,
// a default or a restriction say what the code does.
func TestUsageTextsMatchTheCode(t *testing.T) {
	configPath := unreachableAdminConfig(t, true)
	help := func(args ...string) string {
		out, _ := runAdminMain(t, append([]string{"--config", configPath}, args...)...)
		return out
	}
	check := func(t *testing.T, text string, must, mustNot []string) {
		t.Helper()
		var problems []string
		for _, s := range must {
			if !strings.Contains(text, s) {
				problems = append(problems, "lacks "+strconv.Quote(s))
			}
		}
		for _, s := range mustNot {
			if strings.Contains(text, s) {
				problems = append(problems, "names "+strconv.Quote(s))
			}
		}
		if len(problems) > 0 {
			t.Errorf("text %s:\n%s", strings.Join(problems, ", "), text)
		}
	}

	t.Run("credentials delete names the commands that exist", func(t *testing.T) {
		stale := []string{"update-account", "delete-account"}
		check(t, help("credentials", "delete", "--help"),
			[]string{"sora-admin accounts update --email", "--make-primary", "sora-admin accounts delete"}, stale)
		// Also returned by the Admin API, so they name no sora-admin command either.
		check(t, db.ErrCannotDeletePrimaryCredential.Error(), nil, stale)
		check(t, db.ErrCannotDeleteLastCredential.Error(), nil, stale)
	})

	t.Run("Admin API settings are [admin_cli] addr and api_key", func(t *testing.T) {
		check(t, help("connections", "kick", "--help"), []string{"[admin_cli]"}, []string{"http_api_"})
		out, _ := runAdminMain(t, "--config", unreachableAdminConfig(t, false), "health", "status", "--backends")
		check(t, out, []string{"admin_cli"}, []string{"http_api_"})
	})

	t.Run("connections kick --all is not offered", func(t *testing.T) {
		check(t, help("connections", "--help"), nil, []string{"--all"})
		err := kickConnections(context.Background(), AdminConfig{}, "", "IMAP", "", "", false, true)
		if err == nil {
			t.Fatal("kick without --user succeeded")
		}
		check(t, err.Error(), nil, []string{"--all"})
	})

	t.Run("export names the database it keeps", func(t *testing.T) {
		dir := t.TempDir()
		exporter, err := NewExporter(context.Background(), dir, "user@example.com", 1, nil, nil, ExporterOptions{})
		if err != nil {
			t.Fatal(err)
		}
		exporter.Close()
		dbs, _ := filepath.Glob(filepath.Join(dir, "*.db"))
		if len(dbs) != 1 {
			t.Fatalf("exporter created %v, want one database", dbs)
		}
		check(t, help("export", "maildir", "--help"), []string{filepath.Base(dbs[0])}, []string{"sora-export.db"})
	})

	t.Run("a maildir needs cur/ or new/, not tmp/", func(t *testing.T) {
		// A Maildir with cur/ and no tmp/ is imported, so no text may say tmp/ is required.
		parent, other := t.TempDir(), t.TempDir()
		for _, dir := range []string{filepath.Join(parent, "Maildir", "cur"), filepath.Join(other, "box", "new")} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if !isMaildirFolder(filepath.Join(parent, "Maildir")) {
			t.Fatal("a maildir with cur/ and no tmp/ is not accepted")
		}
		// "Did you mean Maildir", "Found possible maildir(s)", and no maildir at all.
		for _, path := range []string{parent, other, filepath.Join(parent, "Maildir", "cur")} {
			err := (&Importer{maildirPath: path}).scanMaildir()
			if err == nil {
				t.Fatalf("%s accepted as a maildir root", path)
			}
			check(t, err.Error(), nil, []string{"tmp/"})
		}
		check(t, help("import", "maildir", "--help"), nil, []string{"tmp/"})
	})

	t.Run("tls list --cache-dir default is fallback_dir", func(t *testing.T) {
		check(t, help("tls", "list", "--help"),
			[]string{"fallback_dir", "/var/lib/sora/certs"}, []string{"/var/cache/sora/autocert"})
	})

	t.Run("relay queue has no enable switch", func(t *testing.T) {
		check(t, help("relay", "--help"), []string{"[relay]"}, []string{"must be enabled"})
	})

	t.Run("accounts list examples pass --domain", func(t *testing.T) {
		out, _ := runAdminMain(t, "help")
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "accounts list") {
				check(t, line, []string{"--domain"}, nil)
			}
		}
	})
}
