package main

// config.go - Command handlers for config
// Extracted from main.go for better organization

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

func handleConfigCommand(ctx context.Context) {
	// Find the subcommand - skip over --config and its value
	// os.Args format: [prog, --config, PATH, config, SUBCOMMAND, ...]
	var subcommand string
	skipNext := false
	for i := 1; i < len(os.Args); i++ {
		if skipNext {
			skipNext = false
			continue
		}
		if os.Args[i] == "--config" {
			skipNext = true
			continue
		}
		if strings.HasPrefix(os.Args[i], "--config=") {
			continue
		}
		if os.Args[i] == "config" {
			// Skip the "config" command itself
			continue
		}
		if os.Args[i] == "--help" || os.Args[i] == "-h" {
			subcommand = "help"
			break
		}
		if !strings.HasPrefix(os.Args[i], "-") {
			subcommand = os.Args[i]
			break
		}
	}

	if subcommand == "" {
		printConfigUsage()
		os.Exit(1)
	}

	switch subcommand {
	case "dump":
		handleConfigDump(ctx)
	case "validate":
		handleConfigValidate(ctx)
	case "help":
		printConfigUsage()
	default:
		fmt.Printf("Unknown config subcommand: %s\n\n", subcommand)
		printConfigUsage()
		os.Exit(1)
	}
}

func handleConfigValidate(_ context.Context) {
	// Extract config path from os.Args (it was preserved for config subcommand)
	var configFile string

	// Look for --config flag in the original args (the first one counts). --help or -h
	// anywhere but as the --config value prints the usage instead of validating.
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--config" && i+1 < len(os.Args) {
			if configFile == "" {
				configFile = os.Args[i+1]
			}
			i++ // the value, even when it starts with "-"
		} else if strings.HasPrefix(os.Args[i], "--config=") {
			if configFile == "" {
				configFile = strings.TrimPrefix(os.Args[i], "--config=")
			}
		} else if os.Args[i] == "--help" || os.Args[i] == "-h" {
			printConfigValidateUsage()
			return
		}
	}

	if configFile == "" {
		fmt.Printf("Error: --config is required\n\n")
		printConfigValidateUsage()
		os.Exit(1)
	}

	fmt.Printf("Validating configuration file: %s\n\n", configFile)

	// Load full configuration as the server does - this will show all warnings
	var cfg config.Config
	if err := config.LoadServerConfig(configFile, &cfg); err != nil {
		fmt.Printf("[FAIL] Configuration validation FAILED:\n")
		fmt.Printf("   %v\n", err)
		os.Exit(1)
	}

	// The shared checks the server runs before service setup.
	problems := cfg.Validate()
	for _, p := range problems {
		fmt.Printf("[FAIL] %s:\n   %v\n", p.Section, p.Err)
	}
	if len(problems) > 0 {
		fmt.Printf("\n[FAIL] Configuration validation FAILED with errors\n")
		os.Exit(1)
	}

	fmt.Printf("[OK] Configuration is valid!\n")
	if allServers := cfg.GetAllServers(); len(allServers) > 0 {
		fmt.Printf("\nConfigured servers:\n")
		for _, server := range allServers {
			fmt.Printf("  - %s listening on %s\n", server.Name, server.Addr)
		}
	}
}

func handleConfigDump(_ context.Context) {
	// Extract config path from os.Args (it was preserved for config subcommand;
	// the first --config counts, matching handleConfigValidate) and collect any
	// flags after "dump" with --config stripped.
	var configFile string
	var format string = "toml"
	var maskSecrets bool = true

	seenDump := false
	var dumpArgs []string
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--config" {
			if i+1 < len(os.Args) {
				if configFile == "" {
					configFile = os.Args[i+1]
				}
				i++ // the value, even when it starts with "-" or is "dump"
			}
			continue
		}
		if strings.HasPrefix(os.Args[i], "--config=") {
			if configFile == "" {
				configFile = strings.TrimPrefix(os.Args[i], "--config=")
			}
			continue
		}
		if !seenDump {
			if os.Args[i] == "dump" {
				seenDump = true
			}
			continue
		}
		dumpArgs = append(dumpArgs, os.Args[i])
	}

	// Parse additional flags after the subcommand
	flagSet := flag.NewFlagSet("config-dump", flag.ExitOnError)
	flagSet.StringVar(&format, "format", "toml", "Output format: toml or json")
	flagSet.BoolVar(&maskSecrets, "mask-secrets", true, "Mask sensitive values (passwords, keys, URL userinfo and query values)")
	flagSet.Usage = func() {
		fmt.Printf(`Dump the parsed configuration for debugging

Usage:
  sora-admin --config PATH config dump [options]

Options:
  --format FORMAT      Output format: toml or json (default: toml)
  --mask-secrets       Mask sensitive values: passwords, keys, and the userinfo
                       and query values of URLs (default: true)

Examples:
  sora-admin --config sora.config.toml config dump
  sora-admin --config sora.config.toml config dump --format json --mask-secrets=false
`)
	}

	if len(dumpArgs) > 0 {
		flagSet.Parse(dumpArgs)
	}

	if configFile == "" {
		fmt.Printf("Error: --config is required\n\n")
		flagSet.Usage()
		os.Exit(1)
	}

	// Load the configuration as the server runs with it: without the [database.write]
	// and [database.read] endpoints the file does not define, which NewDefaultConfig
	// seeds only for the keys a table in the file leaves out.
	var cfg config.Config
	if err := config.LoadServerConfig(configFile, &cfg); err != nil {
		logger.Fatalf("Failed to load config file: %v", err)
	}

	// Mask secrets if requested
	if maskSecrets {
		config.MaskSecrets(&cfg)
	}

	// Output in requested format
	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(cfg); err != nil {
			logger.Fatalf("Failed to encode config as JSON: %v", err)
		}
	case "toml":
		encoder := toml.NewEncoder(os.Stdout)
		if err := encoder.Encode(cfg); err != nil {
			logger.Fatalf("Failed to encode config as TOML: %v", err)
		}
	default:
		logger.Fatalf("Unknown format: %s (supported: toml, json)", format)
	}
}

func printConfigValidateUsage() {
	fmt.Printf(`Validate configuration file syntax and settings

Usage:
  sora-admin --config PATH config validate

Description:
  Validates the configuration file by:
  - Checking TOML syntax
  - Detecting duplicate keys (warns and uses first occurrence)
  - Detecting unknown/deprecated keys (warns)
  - Detecting common typos (e.g., 'f' instead of 'false')
  - Running the shared checks the server makes before service setup: the [[server]]
    blocks (at least one; no duplicate names or addresses), [[pool]], [relay],
    trusted_networks, [shared_mailboxes], and [uploader] and [cleanup] when a
    mail backend (imap, lmtp, pop3) runs. Every problem is reported.

  This does not check required database/S3 settings, S3 timeout, connectivity,
  or the node's disk. Those are still checked when services start.

  Exit codes:
    0 - Configuration is valid (warnings OK)
    1 - Configuration has errors

Examples:
  sora-admin --config sora.config.toml config validate
`)
}

func printConfigUsage() {
	fmt.Printf(`Configuration Management

Usage:
  sora-admin --config PATH config <subcommand> [options]

Subcommands:
  validate Validate configuration file syntax and settings
  dump     Dump the parsed configuration for debugging

Examples:
  sora-admin --config sora.config.toml config validate
  sora-admin --config sora.config.toml config dump
  sora-admin --config sora.config.toml config dump --format json --mask-secrets=false

Use 'sora-admin --config PATH config <subcommand> --help' for detailed help.
`)
}
