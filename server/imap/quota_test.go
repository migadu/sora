package imap

import (
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
)

func TestQuotaData(t *testing.T) {
	limit := int64(10<<20 + 1023) // a limit that is not whole KiB rounds down
	for _, tc := range []struct {
		name  string
		quota db.AccountQuota
		want  *imap.QuotaResourceData // nil: no STORAGE resource
	}{
		{name: "unlimited", quota: db.AccountQuota{StorageUsed: 5000}},
		{name: "empty", quota: db.AccountQuota{StorageQuota: &limit}, want: &imap.QuotaResourceData{Usage: 0, Limit: 10 << 10}},
		{name: "one byte reads as 1 KiB", quota: db.AccountQuota{StorageQuota: &limit, StorageUsed: 1}, want: &imap.QuotaResourceData{Usage: 1, Limit: 10 << 10}},
		{name: "whole KiB", quota: db.AccountQuota{StorageQuota: &limit, StorageUsed: 2048}, want: &imap.QuotaResourceData{Usage: 2, Limit: 10 << 10}},
		{name: "drifted negative", quota: db.AccountQuota{StorageQuota: &limit, StorageUsed: -7}, want: &imap.QuotaResourceData{Usage: 0, Limit: 10 << 10}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := quotaData(&tc.quota)
			if data.Root != "" {
				t.Errorf("root = %q, want \"\"", data.Root)
			}
			got, ok := data.Resources[imap.QuotaResourceStorage]
			switch {
			case tc.want == nil && (ok || len(data.Resources) != 0):
				t.Errorf("want no resources, got %v", data.Resources)
			case tc.want != nil && (!ok || got != *tc.want):
				t.Errorf("STORAGE = %+v (present %v), want %+v", got, ok, *tc.want)
			}
		})
	}
}

func TestQuotaResourceTypesIsStorageOnly(t *testing.T) {
	got := (&IMAPSession{}).QuotaResourceTypes()
	if len(got) != 1 || got[0] != imap.QuotaResourceStorage {
		t.Fatalf("QuotaResourceTypes() = %v, want [STORAGE]", got)
	}
}

// disabled_caps = ["QUOTA"] withdraws the capability, every QUOTA command and
// STATUS DELETED-STORAGE; with QUOTA on, CAPABILITY lists QUOTA=RES-STORAGE.
func TestQuotaWithdrawnByDisabledCaps(t *testing.T) {
	on := dialWireListServer(t, IMAPServerOptions{})
	caps := on.mustOK("CAPABILITY")
	if !strings.Contains(caps, " QUOTA ") || !strings.Contains(caps, " QUOTA=RES-STORAGE") {
		t.Fatalf("CAPABILITY lacks QUOTA or QUOTA=RES-STORAGE:\n%s", caps)
	}

	off := dialWireListServer(t, IMAPServerOptions{DisabledCaps: []string{"QUOTA"}})
	caps = off.mustOK("CAPABILITY")
	if strings.Contains(caps, "QUOTA") {
		t.Fatalf("disabled_caps = [QUOTA] still advertises it:\n%s", caps)
	}
	for _, cmd := range []string{
		`GETQUOTAROOT INBOX`,
		`GETQUOTA ""`,
		`SETQUOTA "" (STORAGE 1)`,
		`STATUS INBOX (DELETED-STORAGE)`,
	} {
		off.mustBad(cmd)
	}
}
