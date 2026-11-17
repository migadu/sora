package main

import (
	"github.com/migadu/sora/helpers"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParseMessageMetadataHeaderPresence(t *testing.T) {
	i := &Importer{}
	m, err := i.parseMessageMetadata([]byte("From:\r\nTo: undisclosed:;\r\nCc: invalid list\r\n\r\nbody"), "message", t.TempDir()+"/message")
	require.NoError(t, err)
	require.NotNil(t, m.headerPresence)
	for _, key := range []string{"from", "to", "cc"} {
		bit, _ := helpers.HeaderPresenceBit(key)
		require.NotZero(t, *m.headerPresence&bit, key)
	}
	bit, _ := helpers.HeaderPresenceBit("subject")
	require.Zero(t, *m.headerPresence&bit)
	require.Empty(t, m.recipients, "presence must not be inferred from valid addresses")
	require.Nil(t, m.messageIDRaw)
}

func TestParseMessageMetadataMessageIDRaw(t *testing.T) {
	i := &Importer{}
	m, err := i.parseMessageMetadata([]byte("From: a@example.com\r\nMessage-ID: (ImportedComment) <imp@example.com>\r\n\r\nbody"), "message", t.TempDir()+"/message")
	require.NoError(t, err)
	require.NotNil(t, m.messageIDRaw)
	require.Equal(t, "(ImportedComment) <imp@example.com>", *m.messageIDRaw)

	canonical, err := i.parseMessageMetadata([]byte("From: a@example.com\r\nMessage-ID: <imp@example.com>\r\n\r\nbody"), "message", t.TempDir()+"/message")
	require.NoError(t, err)
	require.Nil(t, canonical.messageIDRaw)
}
