// Command check-closing-refs fails when the text on its standard input puts a GitHub
// closing keyword in front of a reference to another repository, or to a pull request.
//
// GitHub acts on close, fix and resolve (and their -s and -d forms, in any case, with or
// without a colon) in a pull request's description and in its commit messages when they
// merge into the default branch. It closes what the keyword names, in other repositories
// too, and "Merging the referencing pull request also closes the referenced pull
// request". Sora descriptions that wrote the keyword in front of go-imap pull requests
// closed them unmerged (#1646). A Sora pull request closes Sora issues only; it refers to
// anything else without a keyword, for example "Depends on migadu/go-imap#227".
//
// The closing-references workflow pipes a pull request's description and commit messages
// through it. To check a description before opening the pull request:
//
//	go run ./scripts/check-closing-refs < body.md
package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// closingRef matches a closing keyword and the reference right after it, the only one
// the keyword applies to: "OWNER/REPO#N" or an issue or pull request URL. The two may be
// split by a line break, as a wrapped line splits them, but not by a blank line: that ends
// the paragraph, or a commit's subject. A bare "#N" is an issue or pull request in this
// repository and is not matched; which of the two it is cannot be told from the text.
var closingRef = regexp.MustCompile(`(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b:?[ \t]*(?:\r?\n[ \t]*)?\[?` +
	`(?:https?://(?:www\.)?github\.com/([\w-]+)/([\w.-]+)/(issues|pull)/\d+` +
	`|([\w-]+)/([\w.-]+)#\d+)`)

// closingRefs returns each closing keyword in text that would close something other than
// an issue of repo ("owner/name"), with the reference it names.
func closingRefs(text, repo string) []string {
	var found []string
	for _, m := range closingRef.FindAllStringSubmatch(text, -1) {
		owner, name, kind := m[1], m[2], m[3]
		if owner == "" {
			owner, name, kind = m[4], m[5], "issues"
		}
		if kind == "pull" || !strings.EqualFold(owner+"/"+name, repo) {
			found = append(found, m[0])
		}
	}
	return found
}

func run(in io.Reader, out io.Writer, repo string) int {
	text, err := io.ReadAll(in)
	if err != nil {
		fmt.Fprintln(out, "check-closing-refs:", err)
		return 2
	}
	found := closingRefs(string(text), repo)
	for _, ref := range found {
		fmt.Fprintf(out, "%q closes what it names when this pull request merges, merged or not.\n", ref)
	}
	if len(found) > 0 {
		fmt.Fprintf(out, "Use closing keywords only for %s issues. Refer to other pull requests and repositories without one, for example \"Depends on migadu/go-imap#227\".\n", repo)
		return 1
	}
	return 0
}

func main() {
	repo := os.Getenv("GITHUB_REPOSITORY")
	if repo == "" {
		repo = "migadu/sora"
	}
	os.Exit(run(os.Stdin, os.Stdout, repo))
}
