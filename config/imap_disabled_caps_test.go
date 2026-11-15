package config

import (
	"strings"
	"testing"
)

func TestConfigValidate_IMAPDisabledCapsMustKeepBaseVersion(t *testing.T) {
	const imapHeader = "\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:143\"\n"

	for _, tc := range []struct {
		name         string
		disabledCaps string
	}{
		{"both versions", `disabled_caps = ["IMAP4rev1", "IMAP4rev2"]`},
		{"rev1 and MOVE", `disabled_caps = ["IMAP4rev1", "MOVE"]`},
		{"rev1 and IDLE", `disabled_caps = ["IMAP4rev1", "IDLE"]`},
		{"rev1 and ESEARCH", `disabled_caps = ["IMAP4rev1", "ESEARCH"]`},
		{"rev1 and SEARCHRES", `disabled_caps = ["IMAP4rev1", "SEARCHRES"]`},
		{"rev1 and CHILDREN", `disabled_caps = ["IMAP4rev1", "CHILDREN"]`},
	} {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			problems := validateFile(t, storageTOML+imapHeader+tc.disabledCaps+"\n")
			if len(problems) != 1 {
				t.Fatalf("Validate() = %v, want 1 problem", problems)
			}
			if problems[0].Section != "server 'imap'" {
				t.Errorf("Section = %q, want %q", problems[0].Section, "server 'imap'")
			}
			for _, want := range []string{"disabled_caps", "IMAP4rev1", "IMAP4rev2"} {
				if !strings.Contains(problems[0].Err.Error(), want) {
					t.Errorf("error %q does not mention %q", problems[0].Err, want)
				}
			}
		})
	}

	for _, tc := range []struct {
		name    string
		content string
	}{
		{"rev2 only", imapHeader + `disabled_caps = ["IMAP4rev1"]` + "\n"},
		{"rev1 only", imapHeader + `disabled_caps = ["IMAP4rev2"]` + "\n"},
		{"rev1 via MOVE", imapHeader + `disabled_caps = ["MOVE"]` + "\n"},
		{"rev2 without SORT", imapHeader + `disabled_caps = ["IMAP4rev1", "SORT"]` + "\n"},
		{"rev2 without CONDSTORE", imapHeader + `disabled_caps = ["IMAP4rev1", "CONDSTORE"]` + "\n"},
		{"rev2 with always-advertised cap", imapHeader + `disabled_caps = ["IMAP4rev1", "SASL-IR"]` + "\n"},
		{"disabled imap block", imapHeader + "\n[[server]]\nenabled = false\ntype = \"imap\"\nname = \"imap-off\"\naddr = \"127.0.0.1:1143\"\ndisabled_caps = [\"IMAP4rev1\", \"IMAP4rev2\"]\n"},
		{"imap_proxy ignores disabled_caps", "\n[[server]]\ntype = \"imap_proxy\"\nname = \"imap-proxy\"\naddr = \"127.0.0.1:1143\"\nremote_addrs = [\"192.0.2.10:143\"]\ndisabled_caps = [\"IMAP4rev1\", \"IMAP4rev2\"]\n"},
	} {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			if problems := validateFile(t, storageTOML+tc.content); len(problems) != 0 {
				t.Errorf("Validate() = %v, want no problems", problems)
			}
		})
	}
}
