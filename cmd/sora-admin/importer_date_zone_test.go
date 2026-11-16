package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Maildir metadata must carry source-zone status separately from the parsed
// instant so both the single and batch importer can persist it explicitly.
func TestParseMessageMetadataDateZoneStatus(t *testing.T) {
	for _, tc := range []struct {
		name, date      string
		unknown, noDate bool
	}{
		{name: "numeric UTC", date: "Tue, 01 Jan 2019 12:00:00 +0000"},
		{name: "UT", date: "Tue, 01 Jan 2019 12:00:00 UT"},
		{name: "GMT", date: "Tue, 01 Jan 2019 12:00:00 GMT"},
		{name: "unknown numeric zone", date: "Tue, 01 Jan 2019 12:00:00 -0000", unknown: true},
		{name: "malformed GMT offset", date: "Tue, 01 Jan 2019 12:00:00 GMT+1", unknown: true},
		{name: "military zone", date: "Tue, 01 Jan 2019 12:00:00 Z", unknown: true},
		{name: "missing Date", noDate: true},
		{name: "invalid Date", date: "not-a-valid-date", noDate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := ""
			if tc.date != "" {
				header = "Date: " + tc.date + "\r\n"
			}
			metadata, err := (&Importer{}).parseMessageMetadata([]byte(header+"Subject: Test\r\n\r\nBody"), "test.eml", "/dummy/path")
			require.NoError(t, err)
			require.Equal(t, tc.unknown, metadata.sentDateUnknownZone)
			require.Equal(t, tc.noDate, metadata.sentDate.IsZero())
			if !tc.noDate {
				require.True(t, metadata.sentDate.Equal(time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)))
			}
		})
	}
}
