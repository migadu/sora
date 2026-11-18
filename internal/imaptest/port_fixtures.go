package imaptest

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"
)

const upstreamRevision = "0682be5f3617149e55cb6a2f4de4b23be8092c53"

// These message fixtures retain their upstream MIT attribution in testdata/imaptest/COPYING.
//
//go:embed testdata/imaptest/*.mbox testdata/imaptest/COPYING testdata/imaptest/NOTICE testdata/imaptest/coverage.json
var portFixtures embed.FS

func portCase(name, description, rfc string, requires []string, run func(*Session) error) Case {
	return Case{Name: "imaptest/" + name, Description: description, RFC: rfc, Requires: requires, Upstream: name, Run: run}
}

func portFixture(name string) ([][]byte, error) {
	messages, _, err := portReadFixture(name)
	return messages, err
}

func portFixtureDates(name string) ([]string, error) {
	_, dates, err := portReadFixture(name)
	return dates, err
}

func portReadFixture(name string) ([][]byte, []string, error) {
	if strings.ContainsAny(name, "/\\") {
		return nil, nil, fmt.Errorf("invalid fixture name %q", name)
	}
	data, err := portFixtures.ReadFile("testdata/imaptest/" + name + ".mbox")
	if errors.Is(err, fs.ErrNotExist) {
		data, err = portFixtures.ReadFile("testdata/imaptest/default.mbox")
	}
	if err != nil {
		return nil, nil, err
	}
	return portParseMbox(data)
}

// portParseMbox mirrors the upstream fixture loader's message boundaries and
// octet conversion, without interpreting RFC 5322 message content as UTF-8.
func portParseMbox(data []byte) ([][]byte, []string, error) {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	var messages [][]byte
	var dates []string
	var message []byte
	started := false
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, []byte("From ")) {
			if date, ok := portEnvelopeDate(string(bytes.TrimSuffix(line, []byte("\n")))); ok {
				if started {
					messages = append(messages, message)
				}
				message = nil
				started = true
				dates = append(dates, date)
				continue
			}
		}
		if !started {
			return nil, nil, errors.New("mbox fixture does not start with a valid From envelope")
		}
		message = append(message, bytes.ReplaceAll(line, []byte("\n"), []byte("\r\n"))...)
	}
	if !started || len(message) == 0 {
		return nil, nil, errors.New("empty mbox fixture message")
	}
	messages = append(messages, message)
	return messages, dates, nil
}

func portEnvelopeDate(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 7 || fields[0] != "From" {
		return "", false
	}
	value := strings.Join(fields[2:], " ")
	for _, layout := range []string{"Mon Jan 2 15:04:05 2006 -0700", "Mon Jan 2 15:04:05 2006"} {
		if date, err := time.Parse(layout, value); err == nil {
			return date.Format("02-Jan-2006 15:04:05 -0700"), true
		}
	}
	return "", false
}

// count=-1 appends every fixture message; positive counts wrap in fixture order.
// The returned message slice is the original cycle for subsequent APPENDs.
func portMailbox(s *Session, fixture string, count int, selected bool) (string, [][]byte, error) {
	messages, dates, err := portReadFixture(fixture)
	if err != nil {
		return "", nil, err
	}
	return portPopulateMailbox(s, messages, dates, count, selected)
}

// portIndexedMailbox gives body-search fixtures a current sent date so that a
// server's FTS retention policy permits indexing. Bodies, source fixture files,
// and mbox-envelope INTERNALDATE values remain unchanged.
func portIndexedMailbox(s *Session, fixture string, count int, selected bool) (string, [][]byte, error) {
	messages, dates, err := portReadFixture(fixture)
	if err != nil {
		return "", nil, err
	}
	now := time.Now().UTC()
	for i, message := range messages {
		messages[i], err = portFreshDate(message, now)
		if err != nil {
			return "", nil, err
		}
	}
	return portPopulateMailbox(s, messages, dates, count, selected)
}

func portFreshDate(message []byte, now time.Time) ([]byte, error) {
	header, body, ok := bytes.Cut(message, []byte("\r\n\r\n"))
	if !ok {
		return nil, errors.New("body-search fixture has no header terminator")
	}
	date := []byte("Date: " + now.Format(time.RFC1123Z))
	var output [][]byte
	replaced, skipFold := false, false
	for _, line := range bytes.Split(header, []byte("\r\n")) {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if !skipFold {
				output = append(output, line)
			}
			continue
		}
		skipFold = false
		field, _, _ := bytes.Cut(line, []byte(":"))
		if bytes.EqualFold(field, []byte("Date")) {
			if replaced {
				return nil, errors.New("body-search fixture has duplicate Date headers")
			}
			output = append(output, date)
			replaced = true
			skipFold = true
		} else {
			output = append(output, line)
		}
	}
	if !replaced {
		output = append(output, date)
	}
	fresh := bytes.Join(output, []byte("\r\n"))
	fresh = append(fresh, []byte("\r\n\r\n")...)
	fresh = append(fresh, body...)
	return fresh, nil
}

func portPopulateMailbox(s *Session, messages [][]byte, dates []string, count int, selected bool) (string, [][]byte, error) {
	box, err := s.NewMailbox("messages")
	if err != nil {
		return "", nil, err
	}
	if count < 0 {
		count = len(messages)
	}
	for i := 0; i < count; i++ {
		if _, err := s.Client.Append(box, nil, dates[i%len(dates)], messages[i%len(messages)]); err != nil {
			return "", nil, err
		}
	}
	if selected {
		if _, err := s.Client.OK("SELECT " + Quote(box)); err != nil {
			return "", nil, err
		}
	}
	return box, messages, nil
}
