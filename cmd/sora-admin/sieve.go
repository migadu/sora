package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/migadu/sora/consts"
)

// handleSieveCommand handles the 'sieve' command
func handleSieveCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printSieveUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "list":
		handleSieveList(ctx)
	case "show":
		handleSieveShow(ctx)
	case "put":
		handleSievePut(ctx)
	case "delete":
		handleSieveDelete(ctx)
	case "activate":
		handleSieveActivate(ctx)
	case "deactivate":
		handleSieveDeactivate(ctx)
	case "rename":
		handleSieveRename(ctx)
	case "help", "--help", "-h":
		printSieveUsage()
	default:
		fmt.Printf("Unknown sieve subcommand: %s\n\n", subcommand)
		printSieveUsage()
		os.Exit(1)
	}
}

// handleSieveList lists all Sieve scripts for a user
func handleSieveList(ctx context.Context) {
	fs := flag.NewFlagSet("sieve list", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")

	fs.Usage = func() {
		fmt.Printf(`List Sieve scripts for an account

Usage:
  sora-admin sieve list --config PATH --email EMAIL

Options:
  --config PATH    Path to TOML configuration file (required)
  --email EMAIL    Email address of the account (required)

Examples:
  sora-admin sieve list --config config.toml --email user@example.com
`)
	}

	fs.Parse(os.Args[3:])

	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	scripts, err := rdb.GetUserScriptsWithRetry(ctx, accountID)
	if err != nil {
		fmt.Printf("Failed to retrieve Sieve scripts: %v\n", err)
		os.Exit(1)
	}

	if len(scripts) == 0 {
		fmt.Println("No Sieve scripts found")
		return
	}

	fmt.Printf("Sieve scripts for %s:\n\n", *email)
	fmt.Printf("%-40s %-12s %-12s %-20s\n", "Name", "Active", "Size (bytes)", "Updated")
	fmt.Printf("%-40s %-12s %-12s %-20s\n", "----", "------", "------------", "-------")

	for _, script := range scripts {
		activeStr := "No"
		if script.Active {
			activeStr = "Yes"
		}
		fmt.Printf("%-40s %-12s %-12d %-20s\n",
			script.Name,
			activeStr,
			len(script.Script),
			script.UpdatedAt.Format("2006-01-02 15:04:05"),
		)
	}
}

// handleSieveShow displays the content of a Sieve script
func handleSieveShow(ctx context.Context) {
	fs := flag.NewFlagSet("sieve show", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	name := fs.String("name", "", "Sieve script name (required)")

	fs.Usage = func() {
		fmt.Printf(`Display content of a Sieve script

Usage:
  sora-admin sieve show --config PATH --email EMAIL --name NAME

Options:
  --config PATH    Path to TOML configuration file (required)
  --email EMAIL    Email address of the account (required)
  --name NAME      Sieve script name (required)

Examples:
  sora-admin sieve show --config config.toml --email user@example.com --name "myscript"
`)
	}

	fs.Parse(os.Args[3:])

	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *name == "" {
		fmt.Println("Error: --name is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	script, err := rdb.GetScriptByNameWithRetry(ctx, *name, accountID)
	if err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			fmt.Printf("Script '%s' not found for account %s\n", *name, *email)
		} else {
			fmt.Printf("Failed to retrieve Sieve script: %v\n", err)
		}
		os.Exit(1)
	}

	fmt.Print(script.Script)
}

// handleSievePut creates or updates a Sieve script
func handleSievePut(ctx context.Context) {
	fs := flag.NewFlagSet("sieve put", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	name := fs.String("name", "", "Sieve script name (required)")
	file := fs.String("file", "", "Path to Sieve script file (optional, reads from stdin if omitted or '-')")

	fs.Usage = func() {
		fmt.Printf(`Create or update a Sieve script

Usage:
  sora-admin sieve put --config PATH --email EMAIL --name NAME [--file FILE]

Options:
  --config PATH    Path to TOML configuration file (required)
  --email EMAIL    Email address of the account (required)
  --name NAME      Sieve script name (required)
  --file FILE      Path to Sieve script file (optional, reads from stdin if omitted or '-')

Examples:
  # Upload script from file
  sora-admin sieve put --config config.toml --email user@example.com --name "myscript" --file "/path/to/script.sieve"

  # Upload script from stdin
  cat script.sieve | sora-admin sieve put --config config.toml --email user@example.com --name "myscript"
`)
	}

	fs.Parse(os.Args[3:])

	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *name == "" {
		fmt.Println("Error: --name is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	if err := validateScriptName(*name); err != nil {
		fmt.Printf("Error: invalid script name '%s': %v\n", *name, err)
		os.Exit(1)
	}

	var scriptContent []byte
	var err error
	if *file == "" || *file == "-" {
		scriptContent, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Printf("Failed to read script from stdin: %v\n", err)
			os.Exit(1)
		}
	} else {
		scriptContent, err = os.ReadFile(*file)
		if err != nil {
			fmt.Printf("Failed to read script file: %v\n", err)
			os.Exit(1)
		}
	}

	// 64KB max script size
	if len(scriptContent) > 65536 {
		fmt.Printf("Error: script size exceeds maximum allowed limit of 65536 bytes (got %d bytes)\n", len(scriptContent))
		os.Exit(1)
	}

	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	_, err = rdb.CreateOrUpdateScriptWithRetry(ctx, accountID, *name, string(scriptContent))
	if err != nil {
		fmt.Printf("Failed to save Sieve script: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully saved Sieve script '%s' for account %s\n", *name, *email)
}

// handleSieveDelete deletes a Sieve script
func handleSieveDelete(ctx context.Context) {
	fs := flag.NewFlagSet("sieve delete", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	name := fs.String("name", "", "Sieve script name (required)")

	fs.Usage = func() {
		fmt.Printf(`Delete a Sieve script

Usage:
  sora-admin sieve delete --config PATH --email EMAIL --name NAME

Options:
  --config PATH    Path to TOML configuration file (required)
  --email EMAIL    Email address of the account (required)
  --name NAME      Sieve script name (required)

Examples:
  sora-admin sieve delete --config config.toml --email user@example.com --name "myscript"
`)
	}

	fs.Parse(os.Args[3:])

	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *name == "" {
		fmt.Println("Error: --name is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	err = rdb.DeleteScriptWithRetry(ctx, *name, accountID)
	if err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			fmt.Printf("Script '%s' not found for account %s\n", *name, *email)
		} else {
			fmt.Printf("Failed to delete Sieve script: %v\n", err)
		}
		os.Exit(1)
	}

	fmt.Printf("Successfully deleted Sieve script '%s' for account %s\n", *name, *email)
}

// handleSieveActivate activates a Sieve script (deactivates all others)
func handleSieveActivate(ctx context.Context) {
	fs := flag.NewFlagSet("sieve activate", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	name := fs.String("name", "", "Sieve script name (required)")

	fs.Usage = func() {
		fmt.Printf(`Activate a Sieve script (deactivates all others)

Usage:
  sora-admin sieve activate --config PATH --email EMAIL --name NAME

Options:
  --config PATH    Path to TOML configuration file (required)
  --email EMAIL    Email address of the account (required)
  --name NAME      Sieve script name (required)

Examples:
  sora-admin sieve activate --config config.toml --email user@example.com --name "myscript"
`)
	}

	fs.Parse(os.Args[3:])

	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *name == "" {
		fmt.Println("Error: --name is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	err = rdb.ActivateScriptWithRetry(ctx, *name, accountID)
	if err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			fmt.Printf("Script '%s' not found for account %s\n", *name, *email)
		} else {
			fmt.Printf("Failed to activate Sieve script: %v\n", err)
		}
		os.Exit(1)
	}

	fmt.Printf("Successfully activated Sieve script '%s' for account %s\n", *name, *email)
}

// handleSieveDeactivate deactivates all Sieve scripts for an account
func handleSieveDeactivate(ctx context.Context) {
	fs := flag.NewFlagSet("sieve deactivate", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")

	fs.Usage = func() {
		fmt.Printf(`Deactivate all Sieve scripts for an account

Usage:
  sora-admin sieve deactivate --config PATH --email EMAIL

Options:
  --config PATH    Path to TOML configuration file (required)
  --email EMAIL    Email address of the account (required)

Examples:
  sora-admin sieve deactivate --config config.toml --email user@example.com
`)
	}

	fs.Parse(os.Args[3:])

	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	err = rdb.DeactivateAllScriptsWithRetry(ctx, accountID)
	if err != nil {
		fmt.Printf("Failed to deactivate Sieve scripts: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully deactivated all Sieve scripts for account %s\n", *email)
}

// handleSieveRename renames a Sieve script
func handleSieveRename(ctx context.Context) {
	fs := flag.NewFlagSet("sieve rename", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	oldName := fs.String("old", "", "Current Sieve script name (required)")
	newName := fs.String("new", "", "New Sieve script name (required)")

	fs.Usage = func() {
		fmt.Printf(`Rename a Sieve script

Usage:
  sora-admin sieve rename --config PATH --email EMAIL --old OLD_NAME --new NEW_NAME

Options:
  --config PATH    Path to TOML configuration file (required)
  --email EMAIL    Email address of the account (required)
  --old OLD_NAME   Current Sieve script name (required)
  --new NEW_NAME   New Sieve script name (required)

Examples:
  sora-admin sieve rename --config config.toml --email user@example.com --old "oldname" --new "newname"
`)
	}

	fs.Parse(os.Args[3:])

	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *oldName == "" {
		fmt.Println("Error: --old is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *newName == "" {
		fmt.Println("Error: --new is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	if err := validateScriptName(*newName); err != nil {
		fmt.Printf("Error: invalid new script name '%s': %v\n", *newName, err)
		os.Exit(1)
	}

	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	err = rdb.RenameScriptWithRetry(ctx, accountID, *oldName, *newName)
	if err != nil {
		if errors.Is(err, consts.ErrDBNotFound) {
			fmt.Printf("Script '%s' not found for account %s\n", *oldName, *email)
		} else if errors.Is(err, consts.ErrDBUniqueViolation) {
			fmt.Printf("A script named '%s' already exists for account %s\n", *newName, *email)
		} else {
			fmt.Printf("Failed to rename Sieve script: %v\n", err)
		}
		os.Exit(1)
	}

	fmt.Printf("Successfully renamed Sieve script '%s' to '%s' for account %s\n", *oldName, *newName, *email)
}

// printSieveUsage prints usage information for the 'sieve' command
func printSieveUsage() {
	fmt.Println(`Usage: sora-admin sieve <subcommand> [options]

Subcommands:
  list          List all Sieve scripts for an account
  show          Display content of a Sieve script
  put           Create or update a Sieve script
  delete        Delete a Sieve script
  activate      Activate a Sieve script
  deactivate    Deactivate all Sieve scripts for an account
  rename        Rename a Sieve script

Examples:
  # List all scripts
  sora-admin sieve list --config config.toml --email user@example.com

  # Show script content
  sora-admin sieve show --config config.toml --email user@example.com --name "myscript"

  # Upload script from file
  sora-admin sieve put --config config.toml --email user@example.com --name "myscript" --file "/path/to/script.sieve"

  # Upload script from stdin
  cat script.sieve | sora-admin sieve put --config config.toml --email user@example.com --name "myscript"

  # Delete script
  sora-admin sieve delete --config config.toml --email user@example.com --name "myscript"

  # Activate script
  sora-admin sieve activate --config config.toml --email user@example.com --name "myscript"

  # Deactivate all scripts
  sora-admin sieve deactivate --config config.toml --email user@example.com

  # Rename script
  sora-admin sieve rename --config config.toml --email user@example.com --old "oldname" --new "newname"

For more information on a subcommand, run:
  sora-admin sieve <subcommand> --help`)
}

// validateScriptName validates a Sieve script name
func validateScriptName(name string) error {
	if name == "" {
		return errors.New("script name cannot be empty")
	}

	// Check for invalid characters
	if containsInvalidChars(name) {
		return errors.New("script name contains invalid characters")
	}

	// Check length (reasonable limit)
	if len(name) > 128 {
		return errors.New("script name too long (max 128 characters)")
	}

	return nil
}

// containsInvalidChars checks if a string contains invalid characters for script names
func containsInvalidChars(s string) bool {
	for _, c := range s {
		// Allow alphanumeric, dash, underscore, dot
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return true
		}
	}
	return false
}
