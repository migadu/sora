package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestSubcommandHelpExamplesPassConfig (#1986): every example in a subcommand's --help
// (`sora-admin <group> <subcommand> --help`) passes --config, like the group overviews'
// examples (#1954), so it runs as shown instead of stopping with "--config flag is
// required". The subcommands are those each group's overview names, so a new one is
// covered without touching this test.
func TestSubcommandHelpExamplesPassConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(configPath, []byte("[database]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	top, _ := runAdminMain(t, "--config", configPath, "help")
	groups := sectionFirstWords(top, "Commands")
	if len(groups) == 0 {
		t.Fatalf("no commands listed:\n%s", top)
	}
	walked := 0
	for _, group := range groups {
		if group == "help" || group == "version" {
			continue
		}
		overview, _ := runAdminMain(t, "--config", configPath, group, "help")
		for _, sub := range groupSubcommands(group, overview) {
			walked++
			t.Run(group+" "+sub, func(t *testing.T) {
				t.Parallel()
				out, _ := runAdminMain(t, "--config", configPath, group, sub, "--help")
				if !strings.Contains(out, "Usage") {
					t.Fatalf("no usage printed:\n%s", out)
				}
				for _, line := range examplesSection(out) {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") || !strings.Contains(line, "sora-admin ") {
						continue
					}
					if !passesConfigFlag(strings.Fields(line)) {
						t.Errorf("example omits --config: %s", line)
					}
				}
			})
		}
	}
	if walked < 50 {
		t.Fatalf("walked only %d subcommands; the overviews' format changed?", walked)
	}
}

// sectionFirstWords returns the first word of each line of the "<name>:" section of
// text, which ends at the first blank line.
func sectionFirstWords(text, name string) []string {
	_, rest, ok := strings.Cut(text, "\n"+name+":\n")
	if !ok {
		return nil
	}
	var words []string
	for _, line := range strings.Split(rest, "\n") {
		if strings.TrimSpace(line) == "" {
			break
		}
		words = append(words, strings.Fields(line)[0])
	}
	return words
}

// groupSubcommands returns the subcommands a group overview names: those its Subcommands
// section lists, and, for an overview without one (backends), those its command lines show.
func groupSubcommands(group, overview string) []string {
	var subs []string
	seen := map[string]bool{"help": true}
	add := func(sub string) {
		if !seen[sub] {
			seen[sub] = true
			subs = append(subs, sub)
		}
	}
	for _, sub := range sectionFirstWords(overview, "Subcommands") {
		add(sub)
	}
	if len(subs) == 0 {
		cmdline := regexp.MustCompile(`sora-admin (?:--config \S+ )?` + regexp.QuoteMeta(group) + ` ([a-z][a-z0-9-]*)`)
		for _, m := range cmdline.FindAllStringSubmatch(overview, -1) {
			add(m[1])
		}
	}
	return subs
}

// examplesSection returns the lines of the "Examples:" section of a help text, which ends
// at the next line that is not indented.
func examplesSection(text string) []string {
	_, rest, ok := strings.Cut(text, "\nExamples:\n")
	if !ok {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(rest, "\n") {
		if line != "" && line[0] != ' ' && line[0] != '\t' {
			break
		}
		lines = append(lines, line)
	}
	return lines
}

func passesConfigFlag(fields []string) bool {
	for _, f := range fields {
		if f == "--config" || strings.HasPrefix(f, "--config=") {
			return true
		}
	}
	return false
}
