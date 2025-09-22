package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// DovecotUIDList represents the parsed dovecot-uidlist file
type DovecotUIDList struct {
	Version     int
	UIDValidity uint32
	NextUID     uint32
	GlobalUID   string
	UIDMappings map[string]uint32 // filename -> UID
}

// ParseDovecotUIDList parses a dovecot-uidlist file from the given maildir path
func ParseDovecotUIDList(maildirPath string) (*DovecotUIDList, error) {
	uidlistPath := filepath.Join(maildirPath, "dovecot-uidlist")

	file, err := os.Open(uidlistPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No uidlist file, return nil (not an error for maildir without one)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open dovecot-uidlist: %w", err)
	}
	defer file.Close()

	return parseDovecotUIDListFromReader(file)
}

// parseDovecotUIDListFromReader parses the uidlist from an io.Reader
func parseDovecotUIDListFromReader(r io.Reader) (*DovecotUIDList, error) {
	scanner := bufio.NewScanner(r)
	uidlist := &DovecotUIDList{
		UIDMappings: make(map[string]uint32),
	}

	// First line is the header
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read header: %w", err)
		}
		return nil, fmt.Errorf("empty dovecot-uidlist file")
	}

	// Parse header line
	headerLine := scanner.Text()
	if err := parseHeader(headerLine, uidlist); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Parse UID mappings
	lineNum := 1
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if err := parseUIDMapping(line, uidlist); err != nil {
			return nil, fmt.Errorf("failed to parse UID mapping at line %d: %w", lineNum, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading dovecot-uidlist: %w", err)
	}

	return uidlist, nil
}

// parseHeader parses the header line of dovecot-uidlist
// Format: "3 V1275660208 N25022 G3085f01b7f11094c501100008c4a11c1"
func parseHeader(line string, uidlist *DovecotUIDList) error {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return fmt.Errorf("invalid header format: %s", line)
	}

	// Parse version
	version, err := strconv.Atoi(fields[0])
	if err != nil {
		return fmt.Errorf("invalid version number: %s", fields[0])
	}
	uidlist.Version = version

	// Parse remaining fields
	for _, field := range fields[1:] {
		if len(field) < 2 {
			continue
		}

		switch field[0] {
		case 'V':
			// UIDVALIDITY
			val, err := strconv.ParseUint(field[1:], 10, 32)
			if err != nil {
				return fmt.Errorf("invalid UIDVALIDITY: %s", field)
			}
			uidlist.UIDValidity = uint32(val)
		case 'N':
			// Next UID
			val, err := strconv.ParseUint(field[1:], 10, 32)
			if err != nil {
				return fmt.Errorf("invalid Next UID: %s", field)
			}
			uidlist.NextUID = uint32(val)
		case 'G':
			// Global UID
			uidlist.GlobalUID = field[1:]
		}
	}

	if uidlist.UIDValidity == 0 {
		return fmt.Errorf("missing UIDVALIDITY in header")
	}

	return nil
}

// parseUIDMapping parses a UID mapping line
// Format: "25006 :1276528487.M364837P9451.kurkku,S=1355,W=1394:2,"
// or with extensions: "25017 W2481 :1276533073.M242911P3632.kurkku:2,F"
func parseUIDMapping(line string, uidlist *DovecotUIDList) error {
	// Find the colon that separates UID/extensions from filename
	colonIdx := strings.Index(line, ":")
	if colonIdx == -1 {
		return fmt.Errorf("invalid UID mapping format: missing colon")
	}

	// Parse UID (first field before colon)
	uidPart := strings.TrimSpace(line[:colonIdx])
	fields := strings.Fields(uidPart)
	if len(fields) == 0 {
		return fmt.Errorf("missing UID")
	}

	uid, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid UID: %s", fields[0])
	}

	// Extract filename (everything after the colon)
	filename := strings.TrimSpace(line[colonIdx+1:])
	if filename == "" {
		return fmt.Errorf("missing filename")
	}

	// Extract the base filename without flags
	// The filename may be like: 1276528487.M364837P9451.kurkku,S=1355,W=1394:2,
	// We want to extract just: 1276528487.M364837P9451.kurkku
	baseFilename := filename

	// First, remove anything after the first comma (size info like ,S=1355,W=1394)
	if idx := strings.Index(baseFilename, ","); idx > 0 {
		baseFilename = baseFilename[:idx]
	}

	// Then remove anything after colon (flags like :2,S)
	if idx := strings.Index(baseFilename, ":"); idx > 0 {
		baseFilename = baseFilename[:idx]
	}

	baseFilename = filepath.Base(baseFilename)

	uidlist.UIDMappings[baseFilename] = uint32(uid)

	return nil
}

// GetUIDForFile returns the UID for a given maildir filename
func (u *DovecotUIDList) GetUIDForFile(filename string) (uint32, bool) {
	if u == nil {
		return 0, false
	}

	// Try exact match first
	if uid, ok := u.UIDMappings[filename]; ok {
		return uid, true
	}

	// Try base filename without flags
	baseFilename := filepath.Base(filename)
	if idx := strings.LastIndex(baseFilename, ":"); idx > 0 {
		baseFilename = baseFilename[:idx]
	}

	uid, ok := u.UIDMappings[baseFilename]
	return uid, ok
}

// WriteDovecotUIDList writes a DovecotUIDList to the specified maildir path
func WriteDovecotUIDList(maildirPath string, uidList *DovecotUIDList) error {
	if uidList == nil {
		return fmt.Errorf("uidList cannot be nil")
	}

	uidlistPath := filepath.Join(maildirPath, "dovecot-uidlist")

	file, err := os.Create(uidlistPath)
	if err != nil {
		return fmt.Errorf("failed to create dovecot-uidlist: %w", err)
	}
	defer file.Close()

	// Write header line - format: "3 V{uidvalidity} N{nextuid} G{globaluid}"
	headerLine := fmt.Sprintf("3 V%d N%d", uidList.UIDValidity, uidList.NextUID)
	if uidList.GlobalUID != "" {
		headerLine += fmt.Sprintf(" G%s", uidList.GlobalUID)
	}
	headerLine += "\n"

	if _, err := file.WriteString(headerLine); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write UID mappings, sorted by UID for consistency
	type uidMapping struct {
		filename string
		uid      uint32
	}

	var mappings []uidMapping
	for filename, uid := range uidList.UIDMappings {
		mappings = append(mappings, uidMapping{filename: filename, uid: uid})
	}

	// Sort by UID
	sort.Slice(mappings, func(i, j int) bool {
		return mappings[i].uid < mappings[j].uid
	})

	// Write each mapping - format: "UID :filename"
	for _, mapping := range mappings {
		line := fmt.Sprintf("%d :%s\n", mapping.uid, mapping.filename)
		if _, err := file.WriteString(line); err != nil {
			return fmt.Errorf("failed to write UID mapping: %w", err)
		}
	}

	return nil
}

// CreateDovecotUIDListFromMessages creates a DovecotUIDList from message data
func CreateDovecotUIDListFromMessages(uidValidity uint32, messages []UIDFileMapping) *DovecotUIDList {
	uidList := &DovecotUIDList{
		Version:     3,
		UIDValidity: uidValidity,
		UIDMappings: make(map[string]uint32),
	}

	var maxUID uint32
	for _, msg := range messages {
		uidList.UIDMappings[msg.Filename] = msg.UID
		if msg.UID > maxUID {
			maxUID = msg.UID
		}
	}

	uidList.NextUID = maxUID + 1
	return uidList
}

// UIDFileMapping represents a UID to filename mapping for export
type UIDFileMapping struct {
	UID      uint32
	Filename string
}
