package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
)

// handleMailboxCommand handles the 'mailbox' command
func handleMailboxCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printMailboxUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "create":
		handleMailboxCreate(ctx)
	case "list":
		handleMailboxList(ctx)
	case "delete":
		handleMailboxDelete(ctx)
	case "rename":
		handleMailboxRename(ctx)
	case "subscribe":
		handleMailboxSubscribe(ctx)
	case "unsubscribe":
		handleMailboxUnsubscribe(ctx)
	case "fix-utf7":
		handleMailboxFixUTF7(ctx)
	case "repair-hierarchy":
		handleMailboxRepairHierarchy(ctx)
	case "repair-unseen":
		handleMailboxRepairUnseen(ctx)
	case "help", "--help", "-h":
		printMailboxUsage()
	default:
		fmt.Printf("Unknown mailbox subcommand: %s\n\n", subcommand)
		printMailboxUsage()
		os.Exit(1)
	}
}

// handleMailboxCreate creates a new mailbox for a user
func handleMailboxCreate(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox create", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	mailbox := fs.String("mailbox", "", "Mailbox name/path to create, e.g., 'Work' or 'Projects/2024' (required)")

	fs.Usage = func() {
		fmt.Printf(`Create a new mailbox for an account

Usage:
  sora-admin mailbox create --config PATH --email EMAIL --mailbox MAILBOX

Options:
  --config PATH       Path to TOML configuration file (required)
  --email EMAIL       Email address of the account (required)
  --mailbox MAILBOX   Mailbox name/path to create (required)

Examples:
  # Create a top-level mailbox
  sora-admin mailbox create --config config.toml --email user@example.com --mailbox "Work"

  # Create a nested mailbox
  sora-admin mailbox create --config config.toml --email user@example.com --mailbox "Projects/2024/Q1"
`)
	}

	fs.Parse(os.Args[3:])

	// Validate required parameters
	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *mailbox == "" {
		fmt.Println("Error: --mailbox is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Get account ID
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	// Create mailbox. With the shared mailbox config in the context, a name in the
	// shared namespace becomes a shared mailbox, as it does from IMAP CREATE; an
	// administrator may create one whatever allow_user_create says.
	sharedMailboxes := globalConfig.SharedMailboxes
	sharedMailboxes.AllowUserCreate = true
	createCtx := context.WithValue(ctx, consts.ConfigContextKey, &config.Config{SharedMailboxes: sharedMailboxes})
	err = rdb.CreateMailboxForUserWithRetry(createCtx, accountID, *mailbox)
	if err != nil {
		fmt.Printf("Failed to create mailbox: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully created mailbox '%s' for account %s\n", *mailbox, *email)
}

// handleMailboxList lists all mailboxes for a user
func handleMailboxList(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox list", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	subscribedOnly := fs.Bool("subscribed", false, "Show only subscribed mailboxes")

	fs.Usage = func() {
		fmt.Printf(`List mailboxes for an account

Usage:
  sora-admin mailbox list --config PATH --email EMAIL [--subscribed]

Options:
  --config PATH    Path to TOML configuration file (required)
  --email EMAIL    Email address of the account (required)
  --subscribed     Show only subscribed mailboxes (default: false)

Examples:
  # List all mailboxes
  sora-admin mailbox list --config config.toml --email user@example.com

  # List only subscribed mailboxes
  sora-admin mailbox list --config config.toml --email user@example.com --subscribed
`)
	}

	fs.Parse(os.Args[3:])

	// Validate required parameters
	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Get account
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	// Get mailboxes
	mailboxes, err := rdb.GetMailboxesForUserWithRetry(ctx, accountID, *subscribedOnly)
	if err != nil {
		fmt.Printf("Failed to list mailboxes: %v\n", err)
		os.Exit(1)
	}

	// Print results
	if len(mailboxes) == 0 {
		fmt.Println("No mailboxes found")
		return
	}

	fmt.Printf("Mailboxes for %s:\n\n", *email)
	fmt.Printf("%-40s %-12s %-10s %-12s\n", "Name", "Subscribed", "Children", "UID Validity")
	fmt.Printf("%-40s %-12s %-10s %-12s\n", "----", "----------", "--------", "------------")

	for _, mbox := range mailboxes {
		subscribed := "No"
		if mbox.Subscribed {
			subscribed = "Yes"
		}
		hasChildren := "No"
		if mbox.HasChildren {
			hasChildren = "Yes"
		}
		fmt.Printf("%-40s %-12s %-10s %-12d\n", mbox.Name, subscribed, hasChildren, mbox.UIDValidity)
	}
}

// handleMailboxDelete deletes a mailbox
func handleMailboxDelete(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox delete", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	mailbox := fs.String("mailbox", "", "Mailbox name/path to delete (required)")
	confirm := fs.Bool("confirm", false, "Confirm deletion without interactive prompt (required)")
	purge := fs.Bool("purge", false, "Expunge all messages in the mailbox and its children (the cleaner reclaims rows and objects after the grace period)")

	fs.Usage = func() {
		fmt.Printf(`Delete a mailbox

Usage:
  sora-admin mailbox delete --config PATH --email EMAIL --mailbox MAILBOX --confirm [--purge]

Options:
  --config PATH       Path to TOML configuration file (required)
  --email EMAIL       Email address of the account (required)
  --mailbox MAILBOX   Mailbox name/path to delete (required)
  --confirm           Confirm deletion (required for safety)
  --purge             Expunge every message in the mailbox first. Rows and S3 objects are then
                      reclaimed by the cleaner after the grace period, once nothing else (a copy
                      in another folder) references each object.

A mailbox that still has child mailboxes is refused (nothing is purged); delete the
children first, as IMAP DELETE requires.

Examples:
  # Delete mailbox (messages enter grace period for cleanup)
  sora-admin mailbox delete --config config.toml --email user@example.com --mailbox "OldFolder" --confirm

  # Delete mailbox and expunge all its messages right away
  sora-admin mailbox delete --config config.toml --email user@example.com --mailbox "OldFolder" --confirm --purge
`)
	}

	fs.Parse(os.Args[3:])

	// Validate required parameters
	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *mailbox == "" {
		fmt.Println("Error: --mailbox is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if !*confirm {
		fmt.Println("Error: --confirm is required for safety")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Get account
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)

	// Refuse INBOX, missing shared-mailbox delete permission, and mailboxes with children
	// BEFORE --purge touches anything. The delete below refuses them anyway, so running
	// --purge first would expunge messages and then leave the mailbox in place, emptied.
	target, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, *mailbox)
	if err != nil {
		fmt.Printf("Failed to find mailbox '%s': %v\n", *mailbox, err)
		os.Exit(1)
	}
	if target.AccountID == accountID && isInboxMailboxName(target.Name) {
		fmt.Println("Failed to delete mailbox: cannot delete INBOX")
		os.Exit(1)
	}
	if target.AccountID != accountID {
		hasDeleteRight, err := rdb.CheckMailboxPermissionWithRetry(ctx, target.ID, accountID, db.ACLRightDelete)
		if err != nil {
			fmt.Printf("Failed to check delete permission on '%s': %v\n", *mailbox, err)
			os.Exit(1)
		}
		if !hasDeleteRight {
			fmt.Printf("Failed to delete mailbox: %v: no delete right on shared mailbox '%s'\n", consts.ErrNotPermitted, *mailbox)
			os.Exit(1)
		}
	}
	// Any live descendant, not only a direct child (HasChildren): the purge also reaches
	// a live grandchild under a mailbox an earlier build tombstoned.
	hasDescendants, err := rdb.HasLiveDescendantsWithRetry(ctx, target.AccountID, target.Path)
	if err != nil {
		fmt.Printf("Failed to check child mailboxes of '%s': %v\n", *mailbox, err)
		os.Exit(1)
	}
	if hasDescendants {
		fmt.Printf("Mailbox '%s' has child mailboxes; delete them first\n", *mailbox)
		os.Exit(1)
	}

	// If purge flag is set, expunge every message now. Only rows are touched: the
	// cleaner reclaims them and their S3 objects after the grace period.
	if *purge {
		fmt.Printf("Purging all messages from mailbox '%s'...\n", *mailbox)

		err = purgeResolvedMailboxMessages(ctx, rdb, target)
		if err != nil {
			fmt.Printf("Failed to purge messages: %v\n", err)
			os.Exit(1)
		}
	}

	// Delete mailbox
	err = rdb.DeleteMailboxForUserWithRetry(ctx, accountID, *mailbox)
	if err != nil {
		fmt.Printf("Failed to delete mailbox: %v\n", err)
		os.Exit(1)
	}

	if *purge {
		fmt.Printf("Successfully purged and deleted mailbox '%s' for account %s\n", *mailbox, *email)
	} else {
		fmt.Printf("Successfully deleted mailbox '%s' for account %s (messages will be cleaned up after grace period)\n", *mailbox, *email)
	}
}

// handleMailboxRename renames or moves a mailbox
func handleMailboxRename(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox rename", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	oldName := fs.String("old-name", "", "Current mailbox name/path (required)")
	newName := fs.String("new-name", "", "New mailbox name/path (required)")

	fs.Usage = func() {
		fmt.Printf(`Rename or move a mailbox

Usage:
  sora-admin mailbox rename --config PATH --email EMAIL --old-name OLD --new-name NEW

Options:
  --config PATH     Path to TOML configuration file (required)
  --email EMAIL     Email address of the account (required)
  --old-name OLD    Current mailbox name/path (required)
  --new-name NEW    New mailbox name/path (required)

Examples:
  # Rename a mailbox
  sora-admin mailbox rename --config config.toml --email user@example.com --old-name "Work" --new-name "Business"

  # Move a mailbox to a different parent
  sora-admin mailbox rename --config config.toml --email user@example.com --old-name "Projects/2024" --new-name "Archive/Projects/2024"
`)
	}

	fs.Parse(os.Args[3:])

	// Validate required parameters
	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *oldName == "" {
		fmt.Println("Error: --old-name is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *newName == "" {
		fmt.Println("Error: --new-name is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Get account
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)

	// Get the mailbox to rename
	mbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, *oldName)
	if err != nil {
		fmt.Printf("Failed to find mailbox '%s': %v\n", *oldName, err)
		os.Exit(1)
	}
	if mbox.AccountID == accountID && isInboxMailboxName(mbox.Name) {
		fmt.Println("Failed to rename mailbox: cannot rename INBOX")
		os.Exit(1)
	}

	// Validate before creating parents, so a refused rename leaves no hierarchy. As on
	// IMAP RENAME, a trailing delimiter is no part of the new name, and a name with an
	// empty, "." or ".." level is refused.
	created, nameErr := helpers.MailboxNameToCreate(*newName)
	// The namespace boundary is checked against the stored flags, as db.RenameMailbox
	// does: a personal mailbox under the shared prefix may only be renamed out of it,
	// and the descendants the rename carries along must stay on their side too.
	crosses := false
	if nameErr == nil {
		crosses, err = rdb.RenameCrossesSharedBoundaryWithRetry(ctx, globalConfig.SharedMailboxes, mbox, created)
		if err != nil {
			fmt.Printf("Failed to check mailbox '%s' against the shared namespace: %v\n", *oldName, err)
			os.Exit(1)
		}
	}
	if nameErr != nil || crosses {
		fmt.Println("Failed to rename mailbox: invalid destination or shared namespace boundary")
		os.Exit(1)
	}
	*newName = created
	// Which level of the new name is the mailbox is the database's call (LOWER(name)
	// under its collation), not a Go case mapping's.
	below, err := rdb.MailboxNameIsBelowWithRetry(ctx, *newName, mbox)
	if err != nil {
		fmt.Printf("Failed to check whether '%s' is below '%s': %v\n", *newName, *oldName, err)
		os.Exit(1)
	}
	if below {
		fmt.Println("Failed to rename mailbox: a mailbox cannot be renamed to a name below itself")
		os.Exit(1)
	}
	renameCtx := context.WithValue(ctx, consts.ConfigContextKey, &config.Config{SharedMailboxes: globalConfig.SharedMailboxes})
	var parentID *int64
	if index := strings.LastIndex(*newName, string(consts.MailboxDelimiter)); index >= 0 {
		parentID, err = rdb.ResolveOrCreateMailboxPathWithRetry(renameCtx, mbox.AccountID, (*newName)[:index])
		if err != nil {
			fmt.Printf("Failed to resolve destination parent: %v\n", err)
			os.Exit(1)
		}
	}
	err = rdb.RenameMailboxWithRetry(renameCtx, mbox.ID, mbox.AccountID, *newName, parentID)
	if err != nil {
		fmt.Printf("Failed to rename mailbox: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully renamed mailbox '%s' to '%s' for account %s\n", *oldName, *newName, *email)
}

// handleMailboxSubscribe subscribes to a mailbox
func handleMailboxSubscribe(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox subscribe", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	mailbox := fs.String("mailbox", "", "Mailbox name/path to subscribe to (required)")

	fs.Usage = func() {
		fmt.Printf(`Subscribe to a mailbox

Usage:
  sora-admin mailbox subscribe --config PATH --email EMAIL --mailbox MAILBOX

Options:
  --config PATH       Path to TOML configuration file (required)
  --email EMAIL       Email address of the account (required)
  --mailbox MAILBOX   Mailbox name/path to subscribe to (required)

Examples:
  sora-admin mailbox subscribe --config config.toml --email user@example.com --mailbox "Work"
`)
	}

	fs.Parse(os.Args[3:])

	// Validate required parameters
	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *mailbox == "" {
		fmt.Println("Error: --mailbox is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Get account
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	// Subscribe to mailbox
	err = rdb.SubscribeToMailboxWithRetry(ctx, accountID, *mailbox)
	if err != nil {
		fmt.Printf("Failed to subscribe to mailbox: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully subscribed to mailbox '%s' for account %s\n", *mailbox, *email)
}

// handleMailboxUnsubscribe unsubscribes from a mailbox
func handleMailboxUnsubscribe(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox unsubscribe", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	mailbox := fs.String("mailbox", "", "Mailbox name/path to unsubscribe from (required)")

	fs.Usage = func() {
		fmt.Printf(`Unsubscribe from a mailbox

Usage:
  sora-admin mailbox unsubscribe --config PATH --email EMAIL --mailbox MAILBOX

Options:
  --config PATH       Path to TOML configuration file (required)
  --email EMAIL       Email address of the account (required)
  --mailbox MAILBOX   Mailbox name/path to unsubscribe from (required)

Examples:
  sora-admin mailbox unsubscribe --config config.toml --email user@example.com --mailbox "Work"
`)
	}

	fs.Parse(os.Args[3:])

	// Validate required parameters
	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *mailbox == "" {
		fmt.Println("Error: --mailbox is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Get account
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	// Unsubscribe from mailbox
	err = rdb.UnsubscribeFromMailboxWithRetry(ctx, accountID, *mailbox)
	if err != nil {
		fmt.Printf("Failed to unsubscribe from mailbox: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully unsubscribed from mailbox '%s' for account %s\n", *mailbox, *email)
}

// handleMailboxFixUTF7 finds and fixes mailbox names that contain un-decoded Modified UTF-7 sequences.
// This can happen when mailboxes were imported from Dovecot without decoding the filesystem names.
func handleMailboxFixUTF7(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox fix-utf7", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (optional, fixes all accounts if omitted)")
	dryRun := fs.Bool("dry-run", false, "Show what would be changed without making changes")

	fs.Usage = func() {
		fmt.Printf(`Fix mailbox names containing un-decoded Modified UTF-7 sequences

This command finds mailbox names that were imported with raw Modified UTF-7
encoding (e.g., from Dovecot) and renames them to proper UTF-8.

For example:
  "R&AOk-pertoire"  ->  "Répertoire"
  "&AMk-l&AOk-ments envoy&AOk-s"  ->  "Éléments envoyés"

Usage:
  sora-admin mailbox fix-utf7 --config PATH [--email EMAIL] [--dry-run]

Options:
  --config PATH    Path to TOML configuration file (required)
  --email EMAIL    Email address of a specific account (optional, all accounts if omitted)
  --dry-run        Show what would be changed without making changes

Examples:
  # Preview changes for all accounts
  sora-admin mailbox fix-utf7 --config config.toml --dry-run

  # Fix all accounts
  sora-admin mailbox fix-utf7 --config config.toml

  # Fix a specific account
  sora-admin mailbox fix-utf7 --config config.toml --email user@example.com
`)
	}

	fs.Parse(os.Args[3:])

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Find affected mailboxes using a regex that matches Modified UTF-7 sequences.
	// Modified UTF-7 uses '&' followed by base64 chars and terminated by '-'.
	// We exclude '&-' (which is a literal ampersand escape).
	const encoded = `&[A-Za-z0-9+,]+-`
	var query string
	var args []any

	if *email != "" {
		accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
		if err != nil {
			fmt.Printf("Failed to find account: %v\n", err)
			os.Exit(1)
		}
		query = `SELECT id, account_id, name, path, COALESCE(is_shared, FALSE) FROM mailboxes WHERE account_id = $1 AND name ~ '` + encoded + `' AND deleted_at IS NULL ORDER BY account_id, name`
		args = []any{accountID}
	} else {
		query = `SELECT id, account_id, name, path, COALESCE(is_shared, FALSE) FROM mailboxes WHERE name ~ '` + encoded + `' AND deleted_at IS NULL ORDER BY account_id, name`
	}

	opDB := rdb.GetOperationalDatabase()

	// With the shared mailbox config, db.RenameMailbox refuses a rename across the
	// shared namespace boundary, as on "mailbox rename" and IMAP RENAME: a personal
	// mailbox whose name decodes onto namespace_prefix stays where it is.
	renameCtx := context.WithValue(ctx, consts.ConfigContextKey, &config.Config{SharedMailboxes: globalConfig.SharedMailboxes})

	// Fetch all affected mailboxes, decode their names, and process them
	// shallowest-first. RenameMailbox cascades name changes to children,
	// so after renaming a parent its children's prefixes are updated.
	// We re-query after each depth level to pick up the cascaded changes.
	// A dry run writes nothing for a query to see: it carries each rename down
	// to the children in memory and keeps the rows the query would still match.

	type candidate struct {
		MailboxID   int64
		AccountID   int64
		MailboxName string
		Path        string
		IsShared    bool
	}

	type dryRunMailbox struct {
		ID       int64
		Name     string
		Path     string
		IsShared bool
	}
	accountMailboxes := make(map[int64][]dryRunMailbox)
	loadAccountMailboxes := func(accountID int64) ([]dryRunMailbox, error) {
		if mboxes, ok := accountMailboxes[accountID]; ok {
			return mboxes, nil
		}
		mRows, err := opDB.WritePool.Query(ctx,
			`SELECT id, name, path, COALESCE(is_shared, FALSE) FROM mailboxes WHERE account_id = $1 AND deleted_at IS NULL`,
			accountID,
		)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", consts.ErrInternalError, err)
		}
		defer mRows.Close()
		var mboxes []dryRunMailbox
		for mRows.Next() {
			var m dryRunMailbox
			if err := mRows.Scan(&m.ID, &m.Name, &m.Path, &m.IsShared); err != nil {
				return nil, fmt.Errorf("%w: %w", consts.ErrInternalError, err)
			}
			mboxes = append(mboxes, m)
		}
		if err := mRows.Err(); err != nil {
			return nil, fmt.Errorf("%w: %w", consts.ErrInternalError, err)
		}
		accountMailboxes[accountID] = mboxes
		return mboxes, nil
	}

	// Keep collision comparisons in PostgreSQL, just like RenameMailbox and
	// mailboxes_account_id_lower_name_unique. Unicode EqualFold is different
	// from database LOWER (for example final sigma and dotted I). The arrays
	// carry simulated successful renames, which a query of stored rows cannot see.
	countConflicts := func(existing, proposed []string) (int, error) {
		var conflicts int
		err := opDB.WritePool.QueryRow(ctx, `
			SELECT COUNT(*) FROM unnest($1::text[]) AS existing(name)
			WHERE EXISTS (SELECT 1 FROM unnest($2::text[]) AS proposed(name)
				WHERE LOWER(existing.name) = LOWER(proposed.name))`, existing, proposed).Scan(&conflicts)
		if err != nil {
			return 0, fmt.Errorf("%w: %w", consts.ErrInternalError, err)
		}
		return conflicts, nil
	}

	checkDryRunRename := func(r candidate, decoded string) error {
		ids, err := helpers.GetIdsFromPath(r.Path)
		if err != nil {
			return err
		}
		var parentID *int64
		if len(ids) > 1 {
			parentID = &ids[len(ids)-2]
		}

		if !helpers.MailboxNameValid(decoded) {
			return consts.ErrMailboxInvalidName
		}

		if globalConfig.SharedMailboxes.Enabled && globalConfig.SharedMailboxes.InNamespace(decoded) != r.IsShared {
			return consts.ErrMailboxSharedBoundary
		}

		if r.IsShared {
			hasAdminRight, err := rdb.CheckMailboxPermissionWithRetry(renameCtx, r.MailboxID, r.AccountID, db.ACLRightAdmin)
			if err != nil {
				return fmt.Errorf("failed to check admin permission: %w", err)
			}
			if !hasAdminRight {
				return fmt.Errorf("permission denied: user does not have admin right on shared mailbox")
			}
		}

		mboxes, err := loadAccountMailboxes(r.AccountID)
		if err != nil {
			return err
		}

		foundSelf := false
		var otherNames []string
		for _, m := range mboxes {
			if m.ID == r.MailboxID {
				foundSelf = true
				continue
			}
			otherNames = append(otherNames, m.Name)
		}
		if !foundSelf {
			return consts.ErrMailboxNotFound
		}
		conflicts, err := countConflicts(otherNames, []string{decoded})
		if err != nil {
			return err
		}
		if conflicts > 0 {
			return consts.ErrMailboxAlreadyExists
		}

		if r.Path == "" {
			return fmt.Errorf("mailbox has invalid empty path (data corruption)")
		}

		if parentID != nil {
			if *parentID == r.MailboxID {
				return fmt.Errorf("mailbox %d cannot be its own parent", r.MailboxID)
			}
			var parentPath, parentName string
			foundParent := false
			for _, m := range mboxes {
				if m.ID == *parentID {
					parentPath, parentName = m.Path, m.Name
					foundParent = true
					break
				}
			}
			if !foundParent {
				return consts.ErrMailboxNotFound
			}
			// RenameMailbox refuses a parent that does not have the parent part of the
			// new name (compared with LOWER), so a mailbox already detached by name from
			// the parent its path links it to is not renamed in place.
			decodedParent := ""
			if i := strings.LastIndex(decoded, string(consts.MailboxDelimiter)); i >= 0 {
				decodedParent = decoded[:i]
			}
			matches, err := countConflicts([]string{parentName}, []string{decodedParent})
			if err != nil {
				return err
			}
			if matches == 0 {
				return consts.ErrMailboxNotFound
			}
			if strings.HasPrefix(parentPath, r.Path) {
				return fmt.Errorf("cannot move mailbox %d into one of its own sub-mailboxes", r.MailboxID)
			}
		}

		var cascadedNames []string
		for _, child := range mboxes {
			if !helpers.IsDescendantOf(child.Path, r.Path) {
				continue
			}
			newName := renamedDescendantName(child.Name, r.MailboxName, decoded)
			if globalConfig.SharedMailboxes.Enabled && globalConfig.SharedMailboxes.InNamespace(newName) != child.IsShared {
				return consts.ErrMailboxSharedBoundary
			}
			cascadedNames = append(cascadedNames, newName)
		}

		if len(cascadedNames) > 0 {
			var unaffectedNames []string
			for _, existing := range mboxes {
				if existing.ID != r.MailboxID && !helpers.IsDescendantOf(existing.Path, r.Path) {
					unaffectedNames = append(unaffectedNames, existing.Name)
				}
			}
			conflicts, err := countConflicts(unaffectedNames, cascadedNames)
			if err != nil {
				return err
			}
			if conflicts > 0 {
				return fmt.Errorf("rename would create conflicting mailbox names (%d conflicts): %w", conflicts, consts.ErrMailboxAlreadyExists)
			}
		}

		return nil
	}

	fixed := 0
	skipped := 0
	failed := 0
	firstQuery := true

	// Track mailbox IDs we've already skipped/failed so we don't retry them
	processedIDs := make(map[int64]bool)

	stillEncoded := regexp.MustCompile(encoded)
	var simulated []candidate // dry run: the rows as its renames so far leave them
	fromDB := true

	for {
		var rows []candidate

		if !fromDB {
			rows = simulated
		} else {
			dbRows, err := opDB.WritePool.Query(ctx, query, args...)
			if err != nil {
				fmt.Printf("Failed to query mailboxes: %v\n", err)
				os.Exit(1)
			}

			for dbRows.Next() {
				var r candidate
				if err := dbRows.Scan(&r.MailboxID, &r.AccountID, &r.MailboxName, &r.Path, &r.IsShared); err != nil {
					fmt.Printf("Failed to scan row: %v\n", err)
					os.Exit(1)
				}
				rows = append(rows, r)
			}
			if err := dbRows.Err(); err != nil {
				fmt.Printf("Failed to iterate mailbox rows: %v\n", err)
				os.Exit(1)
			}
			dbRows.Close()
		}

		// Filter out already-processed IDs
		var unprocessed []candidate
		for _, r := range rows {
			if !processedIDs[r.MailboxID] {
				unprocessed = append(unprocessed, r)
			}
		}

		if len(unprocessed) == 0 {
			if firstQuery {
				fmt.Println("No mailboxes with Modified UTF-7 encoded names found.")
			}
			break
		}

		if firstQuery {
			fmt.Printf("Found %d mailbox(es) with potential Modified UTF-7 names:\n\n", len(unprocessed))
			firstQuery = false
		}

		// Find the shallowest depth (fewest '/' separators) among unprocessed mailboxes
		minDepth := -1
		for _, r := range unprocessed {
			d := strings.Count(r.MailboxName, "/")
			if minDepth == -1 || d < minDepth {
				minDepth = d
			}
		}

		renamedInRound := 0
		for _, r := range unprocessed {
			// Only process mailboxes at the shallowest depth in this round
			if strings.Count(r.MailboxName, "/") != minDepth {
				continue
			}

			decoded, err := decodeMailboxLevelUTF7(r.MailboxName)
			if err != nil {
				fmt.Printf("  SKIP  %-40s  (decode error: %v)\n", r.MailboxName, err)
				skipped++
				processedIDs[r.MailboxID] = true
				continue
			}

			if decoded == r.MailboxName {
				// Regex matched but no actual Modified UTF-7 (e.g., false positive)
				fmt.Printf("  SKIP  %-40s  (no change after decode)\n", r.MailboxName)
				skipped++
				processedIDs[r.MailboxID] = true
				continue
			}

			if *dryRun {
				if dryErr := checkDryRunRename(r, decoded); dryErr != nil {
					fmt.Printf("  WOULD FAIL  account_id=%-6d  %q  ->  %q  (error: %v)\n", r.AccountID, r.MailboxName, decoded, dryErr)
					failed++
					processedIDs[r.MailboxID] = true
					continue
				}

				fmt.Printf("  WOULD RENAME  account_id=%-6d  %q  ->  %q\n", r.AccountID, r.MailboxName, decoded)
				fixed++
				processedIDs[r.MailboxID] = true
				renamedInRound++

				mboxes := accountMailboxes[r.AccountID]
				for j := range mboxes {
					if mboxes[j].ID == r.MailboxID {
						mboxes[j].Name = decoded
					} else if helpers.IsDescendantOf(mboxes[j].Path, r.Path) {
						mboxes[j].Name = renamedDescendantName(mboxes[j].Name, r.MailboxName, decoded)
					}
				}

				// As the rename would, carry the new name down to the children: every
				// descendant its path links below the mailbox, however it spells the
				// mailbox's levels.
				for j := range rows {
					c := &rows[j]
					if c.AccountID == r.AccountID && helpers.IsDescendantOf(c.Path, r.Path) {
						c.MailboxName = renamedDescendantName(c.MailboxName, r.MailboxName, decoded)
					}
				}
				continue
			}

			// Rename in place, under the parent the path links it to: a nil parent
			// would move it to the top level. The rename cascades to its children.
			ids, err := helpers.GetIdsFromPath(r.Path)
			if err == nil {
				var parentID *int64
				if len(ids) > 1 {
					parentID = &ids[len(ids)-2]
				}
				err = rdb.RenameMailboxWithRetry(renameCtx, r.MailboxID, r.AccountID, decoded, parentID)
			}
			if err != nil {
				fmt.Printf("  FAIL  account_id=%-6d  %q  ->  %q  (error: %v)\n", r.AccountID, r.MailboxName, decoded, err)
				failed++
				processedIDs[r.MailboxID] = true
				continue
			}

			fmt.Printf("  OK    account_id=%-6d  %q  ->  %q\n", r.AccountID, r.MailboxName, decoded)
			fixed++
			processedIDs[r.MailboxID] = true
			renamedInRound++
		}

		if *dryRun {
			// What the query would return now: a child that its parent's rename left
			// with no encoded level drops out, as it does from the query.
			simulated, fromDB = nil, false
			for _, r := range rows {
				if stillEncoded.MatchString(r.MailboxName) {
					simulated = append(simulated, r)
				}
			}
		}

		if renamedInRound == 0 {
			// No successful renames at this depth. Continue to next round
			// which will re-query and skip already-processed IDs.
			continue
		}

		// Renames happened — re-query to pick up cascaded name changes
	}

	fmt.Println()
	if *dryRun {
		if failed > 0 {
			fmt.Printf("Dry run complete: %d would be renamed, %d skipped, %d would fail\n", fixed, skipped, failed)
		} else {
			fmt.Printf("Dry run complete: %d would be renamed, %d skipped\n", fixed, skipped)
		}
	} else {
		fmt.Printf("Done: %d renamed, %d skipped, %d failed\n", fixed, skipped, failed)
	}
}

// handleMailboxRepairHierarchy finds mailboxes whose place in the hierarchy (path)
// disagrees with their name and, with --apply, links each under the mailbox its name
// names. See db.RepairMailboxHierarchy.
func handleMailboxRepairHierarchy(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox repair-hierarchy", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (optional, all accounts if omitted)")
	apply := fs.Bool("apply", false, "Repair the mailboxes (default: dry run, change nothing)")
	batchSize := fs.Int("batch-size", 1000, "Accounts read per batch when walking all accounts")

	fs.Usage = func() {
		fmt.Printf(`Find and repair mailboxes whose place in the hierarchy disagrees with their name

LIST, SELECT, APPEND and Sieve fileinto find a mailbox by its name; \HasChildren,
RENAME and DELETE follow its place in the hierarchy. This command lists the
mailboxes where the two disagree and, with --apply, moves each one (with the
mailboxes below it) under the mailbox its name names, creating missing parents
as CREATE does. Names, ids, UIDVALIDITY and messages are kept.

Without --apply it is a dry run: it changes nothing and prints what --apply
would do. Problems:

  root_with_delimiter  "Parent/Child" at the top level
  detached             below a mailbox that is not its name's parent
  parent_deleted       its parent is deleted
  parent_missing       its parent does not exist
  bad_path             the stored path is malformed: reported only (REPORT)

A mailbox whose name's parent does not exist while its place gives it another
name ("X/a/Beta" below "X") is left alone (MANUAL): only the user knows which
name is right. Rename it to that name with "mailbox rename".

Usage:
  sora-admin mailbox repair-hierarchy --config PATH [--email EMAIL] [--apply] [--batch-size N]

Options:
  --config PATH     Path to TOML configuration file (required)
  --email EMAIL     Email address of a specific account (optional, all accounts if omitted)
  --apply           Repair the mailboxes (default: dry run, change nothing)
  --batch-size N    Accounts read per batch when walking all accounts (default 1000)

Examples:
  # List what would be repaired, for all accounts
  sora-admin mailbox repair-hierarchy --config config.toml

  # Repair one account
  sora-admin mailbox repair-hierarchy --config config.toml --email user@example.com --apply
`)
	}

	fs.Parse(os.Args[3:])

	if *batchSize < 1 || *batchSize > db.MaxHierarchyScanAccounts {
		fmt.Printf("Error: --batch-size must be between 1 and %d\n", db.MaxHierarchyScanAccounts)
		os.Exit(1)
	}

	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()
	database := rdb.GetOperationalDatabase()

	// Missing parents are created as CREATE creates them: with the shared mailbox
	// config, a name in the shared namespace is a shared mailbox.
	ctx = context.WithValue(ctx, consts.ConfigContextKey, &config.Config{SharedMailboxes: globalConfig.SharedMailboxes})

	if !*apply {
		fmt.Println("Dry run: nothing is changed. Run with --apply to repair.")
		fmt.Println()
	}

	var repaired, manual, reported, failed int
	repairAccount := func(accountID int64, account string) {
		repairs, err := database.RepairMailboxHierarchy(ctx, accountID, *apply)
		if err != nil {
			fmt.Printf("account_id=%d (%s)\n  FAILED  %v\n", accountID, account, err)
			failed++
			return
		}
		if len(repairs) == 0 {
			return
		}
		fmt.Printf("account_id=%d (%s)\n", accountID, repairs[0].Account)
		for _, r := range repairs {
			action, detail := "", r.Reason
			switch r.Action {
			case db.HierarchyActionRepair:
				repaired++
				action = "REPAIRED"
				if !*apply {
					action = "WOULD REPAIR"
				}
				detail = "-> to the top level"
				if r.Parent != "" {
					detail = fmt.Sprintf("-> under %q", r.Parent)
				}
				if len(r.Created) > 0 {
					quoted := make([]string, len(r.Created))
					for i, name := range r.Created {
						quoted[i] = fmt.Sprintf("%q", name)
					}
					detail += " (creating " + strings.Join(quoted, ", ") + ")"
				}
			case db.HierarchyActionManual:
				manual++
				action = "MANUAL"
			default:
				reported++
				action = "REPORT"
			}
			fmt.Printf("  %-12s  %-19s  %q  %s\n", action, r.Problem, r.Name, detail)
		}
	}

	if *email != "" {
		accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
		if err != nil {
			fmt.Printf("Failed to find account: %v\n", err)
			os.Exit(1)
		}
		repairAccount(accountID, *email)
	} else {
		// Each batch reads only its own accounts' mailboxes and writes nothing; each
		// account with a problem is then repaired in a transaction of its own.
		var after int64
		for {
			if err := ctx.Err(); err != nil {
				fmt.Printf("Interrupted: %v\n", err)
				os.Exit(1)
			}
			problems, last, err := database.FindMailboxHierarchyProblems(ctx, after, *batchSize)
			if err != nil {
				fmt.Printf("Failed to scan accounts after account_id=%d: %v\n", after, err)
				os.Exit(1)
			}
			if last == after {
				break
			}
			for i, p := range problems {
				if i == 0 || problems[i-1].AccountID != p.AccountID {
					repairAccount(p.AccountID, p.Account)
				}
			}
			after = last
		}
	}

	fmt.Println()
	if *apply {
		fmt.Printf("Done: %d repaired, %d need manual handling, %d reported only, %d account(s) failed\n", repaired, manual, reported, failed)
	} else {
		fmt.Printf("Dry run complete: %d would be repaired, %d need manual handling, %d reported only, %d account(s) failed\n", repaired, manual, reported, failed)
	}
	if failed > 0 {
		os.Exit(1)
	}
}

// decodeMailboxLevelUTF7 decodes the last level of a mailbox name from Modified UTF-7
// and keeps the levels above it, which are its ancestors' names. fix-utf7 renames
// shallowest first and a rename carries the new name down to the children, so an
// ancestor that is still encoded was not renamed: the child stays linked under it,
// and its name must keep naming it.
func decodeMailboxLevelUTF7(name string) (string, error) {
	i := strings.LastIndexByte(name, consts.MailboxDelimiter) + 1
	level, err := helpers.DecodeModifiedUTF7(name[i:])
	if err != nil {
		return "", err
	}
	return name[:i] + level, nil
}

// renamedDescendantName is the name db.RenameMailbox gives a descendant called name
// when its ancestor oldName is renamed to newName: newName followed by name's levels
// after as many as oldName has. A descendant is linked below its ancestor by
// LOWER(name), which can spell the ancestor with another number of characters (under
// ICU lower('İ') is "i̇", issue #1650) but never with another number of levels.
func renamedDescendantName(name, oldName, newName string) string {
	delim := string(consts.MailboxDelimiter)
	levels := strings.Split(name, delim)
	n := strings.Count(oldName, delim) + 1
	if n >= len(levels) {
		return newName
	}
	return newName + delim + strings.Join(levels[n:], delim)
}

// printMailboxUsage prints usage information for the 'mailbox' command
func printMailboxUsage() {
	fmt.Println(`Usage: sora-admin mailbox <subcommand> [options]

Subcommands:
  create        Create a new mailbox
  list          List all mailboxes for an account
  delete        Delete a mailbox
  rename        Rename or move a mailbox
  subscribe     Subscribe to a mailbox
  unsubscribe   Unsubscribe from a mailbox
  fix-utf7      Fix mailbox names with un-decoded Modified UTF-7 encoding
  repair-hierarchy Repair mailboxes whose place in the hierarchy disagrees with their name
  repair-unseen Find and repair cached unseen counts that are too high

Examples:
  # Create a new mailbox
  sora-admin mailbox create --config config.toml --email user@example.com --mailbox "Work"

  # List all mailboxes
  sora-admin mailbox list --config config.toml --email user@example.com

  # Delete a mailbox (messages enter grace period)
  sora-admin mailbox delete --config config.toml --email user@example.com --mailbox "OldFolder" --confirm

  # Delete a mailbox and purge all messages immediately
  sora-admin mailbox delete --config config.toml --email user@example.com --mailbox "OldFolder" --confirm --purge

  # Rename a mailbox
  sora-admin mailbox rename --config config.toml --email user@example.com --old-name "Work" --new-name "Business"

  # Subscribe to a mailbox
  sora-admin mailbox subscribe --config config.toml --email user@example.com --mailbox "Work"

  # Unsubscribe from a mailbox
  sora-admin mailbox unsubscribe --config config.toml --email user@example.com --mailbox "Work"

  # Fix mailbox names with un-decoded Modified UTF-7 (preview)
  sora-admin mailbox fix-utf7 --config config.toml --dry-run

  # List mailboxes whose hierarchy disagrees with their name (dry run)
  sora-admin mailbox repair-hierarchy --config config.toml

  # List mailboxes whose cached unseen count is too high (dry run)
  sora-admin mailbox repair-unseen --config config.toml

For more information on a subcommand, run:
  sora-admin mailbox <subcommand> --help --config config.toml`)
}

// isInboxMailboxName reports whether stored, a mailbox name resolved from the database,
// is "INBOX" in any case of its ASCII letters.
func isInboxMailboxName(stored string) bool {
	if len(stored) != len(consts.MailboxInbox) {
		return false
	}
	for i := 0; i < len(stored); i++ {
		c := stored[i]
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c != consts.MailboxInbox[i] {
			return false
		}
	}
	return true
}

// purgeMailboxMessages expunges all messages of a mailbox and its children. The cleaner
// deletes the rows and their S3 objects after the grace period, so no S3 client is needed.
func purgeMailboxMessages(ctx context.Context, rdb *resilient.ResilientDatabase, accountID int64, mailboxName string) error {
	// Get the mailbox
	mbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
	if err != nil {
		return fmt.Errorf("failed to get mailbox: %w", err)
	}
	return purgeResolvedMailboxMessages(ctx, rdb, mbox)
}

func purgeResolvedMailboxMessages(ctx context.Context, rdb *resilient.ResilientDatabase, mbox *db.DBMailbox) error {
	// Get all messages for this mailbox and its children under the mailbox owner's account.
	messages, err := rdb.GetMessagesForMailboxAndChildren(ctx, mbox.AccountID, mbox.ID, mbox.Path)
	if err != nil {
		return fmt.Errorf("failed to get messages for purge: %w", err)
	}

	if len(messages) == 0 {
		fmt.Println("No messages to purge")
		return nil
	}

	fmt.Printf("Found %d messages to purge\n", len(messages))

	// Two-phase deletion, like EXPUNGE: mark the rows expunged and let the cleaner
	// reclaim rows and objects after the grace period, under its per-object lock and
	// only once nothing else references each object. This tool used to delete the
	// objects itself, keyed by (account, hash): a message COPY'd into another folder
	// shares that object, and the copy was left pointing at nothing.
	messageIDs := make([]int64, 0, len(messages))
	for _, msg := range messages {
		messageIDs = append(messageIDs, msg.ID) // rows already expunged are left as they are
	}

	fmt.Printf("Expunging %d messages (objects are reclaimed by the cleaner after the grace period)...\n", len(messageIDs))
	expunged, err := rdb.ExpungeMessagesByIDsWithRetry(ctx, messageIDs)
	if err != nil {
		return fmt.Errorf("failed to expunge messages: %w", err)
	}

	fmt.Printf("Expunged %d messages\n", expunged)

	return nil
}
