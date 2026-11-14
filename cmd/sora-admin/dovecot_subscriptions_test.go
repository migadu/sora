//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/migadu/sora/server"
)

// Dovecot's subscriptions file (src/lib-storage/list/subscription-file.c): a version 2
// file starts with exactly "V\t2\n\n"; each line is one mailbox name whose hierarchy
// levels are joined with TAB, each level tab-escaped. A file without that header is
// read as the old unversioned format, one name per line.

// TestImporter_DovecotSubscriptionsFile imports the subscriptions file of a maildir
// with --dovecot and checks the names the account ends up subscribed to.
func TestImporter_DovecotSubscriptionsFile(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()

	for n, tc := range []struct {
		name    string
		file    string
		want    []string
		notWant []string
	}{
		{
			name: "dovecot version 2",
			file: "V\t2\n\nINBOX\nWork\tProjects\nVendors\nArchives\nSent Items\n",
			// Folder import maps "Archives" to Archive and "Sent Items" to Sent;
			// the subscriptions must name the same mailboxes.
			want:    []string{"INBOX", "Work/Projects", "Vendors", "Archive", "Sent"},
			notWant: []string{"Work", "Projects", "Archives", "Sent Items"},
		},
		{
			name:    "dovecot unversioned",
			file:    "INBOX\nVendors\n",
			want:    []string{"INBOX", "Vendors"},
			notWant: []string{"V"},
		},
		{
			// What sora-admin export wrote before: a one-newline header and
			// '/'-separated names.
			name:    "older sora-admin export",
			file:    "V\t2\nINBOX\nWork/Projects\nVendors\n",
			want:    []string{"INBOX", "Work/Projects", "Vendors"},
			notWant: []string{"V\t2"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			email := fmt.Sprintf("subs-%d@example.com", n)
			createSimpleTestAccount(t, rdb, email, "testpassword123")
			address, err := server.NewAddress(email)
			if err != nil {
				t.Fatal(err)
			}
			accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
			if err != nil {
				t.Fatal(err)
			}

			maildir := filepath.Join(t.TempDir(), "Maildir")
			createMaildirFolder(t, maildir)
			if err := os.WriteFile(filepath.Join(maildir, "subscriptions"), []byte(tc.file), 0o644); err != nil {
				t.Fatal(err)
			}

			importer, err := NewImporter(ctx, maildir, email, 1, rdb, nil, ImporterOptions{
				Dovecot: true, PreserveUIDs: true, TestMode: true, BatchSize: 10,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := importer.Run(); err != nil {
				t.Fatalf("import: %v", err)
			}

			got, err := rdb.GetSubscribedMailboxNamesWithRetry(ctx, accountID)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range tc.want {
				if !slices.Contains(got, name) {
					t.Errorf("not subscribed to %q; subscriptions: %q", name, got)
				}
			}
			for _, name := range tc.notWant {
				if slices.Contains(got, name) {
					t.Errorf("subscribed to %q; subscriptions: %q", name, got)
				}
			}
		})
	}
}

// TestExporter_DovecotSubscriptionsFile checks the exported subscriptions file byte for
// byte against the version 2 format Dovecot reads.
func TestExporter_DovecotSubscriptionsFile(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()

	const email = "subs-export@example.com"
	createSimpleTestAccount(t, rdb, email, "testpassword123")
	address, err := server.NewAddress(email)
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"INBOX", "Vendors", "Work/Projects"} {
		if err := rdb.SubscribeWithRetry(ctx, accountID, name); err != nil {
			t.Fatal(err)
		}
	}

	dir := filepath.Join(t.TempDir(), "export")
	exporter, err := NewExporter(ctx, dir, email, 1, rdb, nil, ExporterOptions{Dovecot: true})
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Close()
	if err := exporter.exportSubscriptions(accountID); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "subscriptions"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "V\t2\n\nINBOX\nVendors\nWork\tProjects\n"
	if string(got) != want {
		t.Errorf("subscriptions file = %q, want %q", got, want)
	}
}
