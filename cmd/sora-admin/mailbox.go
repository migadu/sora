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

	// Refuse a mailbox with children BEFORE --purge touches anything. The delete below
	// refuses it anyway (ErrMailboxHasChildren), but the purge matches the whole subtree,
	// so running it first would expunge every child folder's messages and then leave
	// those folders in place, emptied.
	target, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, *mailbox)
	if err != nil {
		fmt.Printf("Failed to find mailbox '%s': %v\n", *mailbox, err)
		os.Exit(1)
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

		err = purgeMailboxMessages(ctx, rdb, accountID, *mailbox)
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

	// Get the mailbox to rename
	mbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, *oldName)
	if err != nil {
		fmt.Printf("Failed to find mailbox '%s': %v\n", *oldName, err)
		os.Exit(1)
	}

	// Validate before creating parents, so a refused rename leaves no hierarchy. The
	// namespace boundary is checked against the stored flag, as db.RenameMailbox does:
	// a personal mailbox under the shared prefix may only be renamed out of it.
	isShared, err := rdb.IsMailboxSharedWithRetry(ctx, mbox.ID)
	if err != nil {
		fmt.Printf("Failed to check whether mailbox '%s' is shared: %v\n", *oldName, err)
		os.Exit(1)
	}
	// As on IMAP RENAME, a trailing delimiter is no part of the new name, and a name
	// with an empty, "." or ".." level is refused.
	created, nameErr := helpers.MailboxNameToCreate(*newName)
	if nameErr != nil ||
		(globalConfig.SharedMailboxes.Enabled && globalConfig.SharedMailboxes.InNamespace(created) != isShared) {
		fmt.Println("Failed to rename mailbox: invalid destination or shared namespace boundary")
		os.Exit(1)
	}
	*newName = created
	if helpers.MailboxNameIsBelow(*newName, mbox.Name) {
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
		ID   int64
		Name string
		Path string
	}
	accountMailboxes := make(map[int64][]dryRunMailbox)
	loadAccountMailboxes := func(accountID int64) ([]dryRunMailbox, error) {
		if mboxes, ok := accountMailboxes[accountID]; ok {
			return mboxes, nil
		}
		mRows, err := opDB.WritePool.Query(ctx,
			`SELECT id, name, path FROM mailboxes WHERE account_id = $1 AND deleted_at IS NULL`,
			accountID,
		)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", consts.ErrInternalError, err)
		}
		defer mRows.Close()
		var mboxes []dryRunMailbox
		for mRows.Next() {
			var m dryRunMailbox
			if err := mRows.Scan(&m.ID, &m.Name, &m.Path); err != nil {
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
		for _, m := range mboxes {
			if m.ID == r.MailboxID {
				foundSelf = true
				continue
			}
			if strings.EqualFold(m.Name, decoded) {
				return consts.ErrMailboxAlreadyExists
			}
		}
		if !foundSelf {
			return consts.ErrMailboxNotFound
		}

		if r.Path == "" {
			return fmt.Errorf("mailbox has invalid empty path (data corruption)")
		}

		if parentID != nil {
			if *parentID == r.MailboxID {
				return fmt.Errorf("mailbox %d cannot be its own parent", r.MailboxID)
			}
			var parentPath string
			foundParent := false
			for _, m := range mboxes {
				if m.ID == *parentID {
					parentPath = m.Path
					foundParent = true
					break
				}
			}
			if !foundParent {
				return consts.ErrMailboxNotFound
			}
			if strings.HasPrefix(parentPath, r.Path) {
				return fmt.Errorf("cannot move mailbox %d into one of its own sub-mailboxes", r.MailboxID)
			}
		}

		delim := string(consts.MailboxDelimiter)
		oldPrefix := r.MailboxName + delim
		newPrefix := decoded + delim
		oldPrefixRunes := len([]rune(oldPrefix))

		var cascadedNames []string
		for _, child := range mboxes {
			if !helpers.IsDescendantOf(child.Path, r.Path) {
				continue
			}
			childRunes := []rune(child.Name)
			var suffix string
			if oldPrefixRunes <= len(childRunes) {
				suffix = string(childRunes[oldPrefixRunes:])
			}
			cascadedNames = append(cascadedNames, newPrefix+suffix)
		}

		if len(cascadedNames) > 0 {
			exactConflicts := 0
			for _, existing := range mboxes {
				for _, cascaded := range cascadedNames {
					if existing.Name == cascaded {
						exactConflicts++
						break
					}
				}
			}
			if exactConflicts > 0 {
				return fmt.Errorf("rename would create conflicting mailbox names (%d conflicts)", exactConflicts)
			}
			for _, existing := range mboxes {
				if existing.ID == r.MailboxID || helpers.IsDescendantOf(existing.Path, r.Path) {
					continue
				}
				for _, cascaded := range cascadedNames {
					if strings.EqualFold(existing.Name, cascaded) {
						return consts.ErrMailboxAlreadyExists
					}
				}
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

				delim := string(consts.MailboxDelimiter)
				oldPrefix := r.MailboxName + delim
				newPrefix := decoded + delim
				oldPrefixRunes := len([]rune(oldPrefix))
				mboxes := accountMailboxes[r.AccountID]
				for j := range mboxes {
					if mboxes[j].ID == r.MailboxID {
						mboxes[j].Name = decoded
					} else if helpers.IsDescendantOf(mboxes[j].Path, r.Path) {
						childRunes := []rune(mboxes[j].Name)
						var suffix string
						if oldPrefixRunes <= len(childRunes) {
							suffix = string(childRunes[oldPrefixRunes:])
						}
						mboxes[j].Name = newPrefix + suffix
					}
				}

				// As the rename would, carry the new name down to the children.
				for j := range rows {
					c := &rows[j]
					if c.AccountID == r.AccountID && helpers.IsDescendantOf(c.Path, r.Path) && strings.HasPrefix(c.MailboxName, oldPrefix) {
						c.MailboxName = decoded + c.MailboxName[len(r.MailboxName):]
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

  # Fix mailbox names with un-decoded Modified UTF-7 (preview)
  sora-admin mailbox fix-utf7 --config config.toml --dry-run

For more information on a subcommand, run:
  sora-admin mailbox <subcommand> --help`)
}

// purgeMailboxMessages expunges all messages of a mailbox and its children. The cleaner
// deletes the rows and their S3 objects after the grace period, so no S3 client is needed.
func purgeMailboxMessages(ctx context.Context, rdb *resilient.ResilientDatabase, accountID int64, mailboxName string) error {
	// Get the mailbox
	mbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
	if err != nil {
		return fmt.Errorf("failed to get mailbox: %w", err)
	}

	// Get all messages for this mailbox and its children by querying messages with matching path
	messages, err := rdb.GetMessagesForMailboxAndChildren(ctx, accountID, mbox.ID, mbox.Path)
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
