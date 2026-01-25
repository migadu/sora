package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/server/aclservice"
)

// handleACLCommand handles the 'acl' command
func handleACLCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printACLUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "grant":
		handleACLGrant(ctx)
	case "revoke":
		handleACLRevoke(ctx)
	case "list":
		handleACLList(ctx)
	case "help", "--help", "-h":
		printACLUsage()
	default:
		fmt.Printf("Unknown acl subcommand: %s\n\n", subcommand)
		printACLUsage()
		os.Exit(1)
	}
}

// handleACLGrant grants ACL rights to a user or identifier on a mailbox
func handleACLGrant(ctx context.Context) {
	fs := flag.NewFlagSet("acl grant", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the mailbox owner (required)")
	mailbox := fs.String("mailbox", "", "Mailbox name, e.g., 'Shared/Sales' (required)")
	identifier := fs.String("identifier", "", "Email address or 'anyone' (required, can also use --user)")
	user := fs.String("user", "", "Alias for --identifier")
	rights := fs.String("rights", "", "ACL rights string, e.g., 'lrs' (required)")

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

	// Use --user if --identifier is not provided
	targetIdentifier := *identifier
	if targetIdentifier == "" {
		targetIdentifier = *user
	}
	if targetIdentifier == "" {
		fmt.Println("Error: --identifier or --user is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	if *rights == "" {
		fmt.Println("Error: --rights is required")
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

	// Create full config for context (needed for shared mailbox detection)
	fullConfig := &config.Config{
		SharedMailboxes: globalConfig.SharedMailboxes,
	}
	ctxWithConfig := context.WithValue(ctx, consts.ConfigContextKey, fullConfig)

	// Create ACL service
	aclSvc := aclservice.New(rdb)

	// Grant ACL (use context with config)
	err = aclSvc.Grant(ctxWithConfig, *email, *mailbox, targetIdentifier, *rights)
	if err != nil {
		fmt.Printf("Failed to grant ACL: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully granted rights '%s' to '%s' on mailbox '%s' (owner: %s)\n",
		*rights, targetIdentifier, *mailbox, *email)
}

// handleACLRevoke revokes ACL rights from a user or identifier on a mailbox
func handleACLRevoke(ctx context.Context) {
	fs := flag.NewFlagSet("acl revoke", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the mailbox owner (required)")
	mailbox := fs.String("mailbox", "", "Mailbox name, e.g., 'Shared/Sales' (required)")
	identifier := fs.String("identifier", "", "Email address or 'anyone' (required, can also use --user)")
	user := fs.String("user", "", "Alias for --identifier")

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

	// Use --user if --identifier is not provided
	targetIdentifier := *identifier
	if targetIdentifier == "" {
		targetIdentifier = *user
	}
	if targetIdentifier == "" {
		fmt.Println("Error: --identifier or --user is required")
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

	// Create full config for context (needed for shared mailbox detection)
	fullConfig := &config.Config{
		SharedMailboxes: globalConfig.SharedMailboxes,
	}
	ctxWithConfig := context.WithValue(ctx, consts.ConfigContextKey, fullConfig)

	// Create ACL service
	aclSvc := aclservice.New(rdb)

	// Revoke ACL (use context with config)
	err = aclSvc.Revoke(ctxWithConfig, *email, *mailbox, targetIdentifier)
	if err != nil {
		fmt.Printf("Failed to revoke ACL: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully revoked access for '%s' on mailbox '%s' (owner: %s)\n",
		targetIdentifier, *mailbox, *email)
}

// handleACLList lists all ACL entries for a mailbox
func handleACLList(ctx context.Context) {
	fs := flag.NewFlagSet("acl list", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the mailbox owner (required)")
	mailbox := fs.String("mailbox", "", "Mailbox name, e.g., 'Shared/Sales' (required)")

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

	// Create full config for context (needed for shared mailbox detection)
	fullConfig := &config.Config{
		SharedMailboxes: globalConfig.SharedMailboxes,
	}
	ctxWithConfig := context.WithValue(ctx, consts.ConfigContextKey, fullConfig)

	// Create ACL service
	aclSvc := aclservice.New(rdb)

	// List ACLs (use context with config)
	acls, err := aclSvc.List(ctxWithConfig, *email, *mailbox)
	if err != nil {
		fmt.Printf("Failed to list ACLs: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Printf("ACL entries for mailbox '%s' (owner: %s):\n", *mailbox, *email)
	if len(acls) == 0 {
		fmt.Println("  (no ACL entries)")
	} else {
		fmt.Println("  Identifier                    Rights")
		fmt.Println("  -------------------------------  ------")
		for _, acl := range acls {
			fmt.Printf("  %-31s  %s\n", acl.Identifier, acl.Rights)
		}
	}
}

// printACLUsage prints usage information for the 'acl' command
func printACLUsage() {
	fmt.Println(`Usage: sora-admin acl <subcommand> [options]

Subcommands:
  grant   Grant ACL rights to a user or identifier on a mailbox
  revoke  Revoke ACL rights from a user or identifier on a mailbox
  list    List all ACL entries for a mailbox

Examples:
  # Grant read-only access to a user on a shared mailbox
  sora-admin acl grant --email owner@domain.com --mailbox "Shared/Sales" --user bob@domain.com --rights "lrs"

  # Grant access to everyone in the same domain
  sora-admin acl grant --email owner@domain.com --mailbox "Shared/Sales" --identifier "anyone" --rights "lr"

  # Revoke access from a user
  sora-admin acl revoke --email owner@domain.com --mailbox "Shared/Sales" --user bob@domain.com

  # List all ACL entries for a mailbox
  sora-admin acl list --email owner@domain.com --mailbox "Shared/Sales"

ACL Rights:
  l - lookup   (mailbox is visible in listings)
  r - read     (read messages)
  s - seen     (change \Seen flag)
  w - write    (change other flags)
  i - insert   (append/copy messages)
  p - post     (post to submission address)
  k - create   (create child mailboxes)
  x - delete   (delete/rename mailbox)
  t - delete   (set \Deleted flag on messages)
  e - expunge  (expunge deleted messages)
  a - admin    (administer ACL)

For more information on a subcommand, run:
  sora-admin acl <subcommand> --help`)
}
