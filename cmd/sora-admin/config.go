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
		if os.Args[i] == "config" {
			// Skip the "config" command itself
			continue
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
	case "--help", "-h", "help":
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

	// Look for --config flag in the original args
	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--config" && i+1 < len(os.Args) {
			configFile = os.Args[i+1]
			break
		}
	}

	if configFile == "" {
		fmt.Printf(`Error: --config is required

Validate configuration file syntax and settings

Usage:
  sora-admin --config PATH config validate

Description:
  Validates the configuration file by:
  - Checking TOML syntax
  - Detecting duplicate keys (warns and uses first occurrence)
  - Detecting unknown/deprecated keys (warns)
  - Detecting common typos (e.g., 'f' instead of 'false')
  - Validating server configurations
  - Checking for conflicts (duplicate names, addresses)

  Exit codes:
    0 - Configuration is valid (warnings OK)
    1 - Configuration has errors

Examples:
  sora-admin --config sora.config.toml config validate
`)
		os.Exit(1)
	}

	fmt.Printf("Validating configuration file: %s\n\n", configFile)

	// Load full configuration - this will show all warnings
	cfg := config.NewDefaultConfig()
	if err := config.LoadConfigFromFile(configFile, &cfg); err != nil {
		fmt.Printf("❌ Configuration validation FAILED:\n")
		fmt.Printf("   %v\n", err)
		os.Exit(1)
	}

	// Validate all server configurations
	allServers := cfg.GetAllServers()

	if len(allServers) == 0 {
		fmt.Printf("⚠️  Warning: No servers configured\n")
		fmt.Printf("   Please configure at least one server in the config file\n\n")
	}

	hasErrors := false
	for _, server := range allServers {
		if err := server.Validate(); err != nil {
			fmt.Printf("❌ Server '%s' validation failed:\n", server.Name)
			fmt.Printf("   %v\n", err)
			hasErrors = true
		}
	}

	// Check for server name conflicts
	serverNames := make(map[string]bool)
	serverAddresses := make(map[string]string) // addr -> server name
	for _, server := range allServers {
		if serverNames[server.Name] {
			fmt.Printf("❌ Duplicate server name '%s' found\n", server.Name)
			fmt.Printf("   Each server must have a unique name\n")
			hasErrors = true
		}
		serverNames[server.Name] = true

		// Check for address conflicts
		if existingServerName, exists := serverAddresses[server.Addr]; exists {
			fmt.Printf("❌ Duplicate server address '%s' found\n", server.Addr)
			fmt.Printf("   Server '%s' and '%s' cannot bind to the same address\n",
				existingServerName, server.Name)
			hasErrors = true
		}
		serverAddresses[server.Addr] = server.Name
	}

	if hasErrors {
		fmt.Printf("\n❌ Configuration validation FAILED with errors\n")
		os.Exit(1)
	}

	fmt.Printf("✅ Configuration is valid!\n")
	if len(allServers) > 0 {
		fmt.Printf("\nConfigured servers:\n")
		for _, server := range allServers {
			fmt.Printf("  - %s listening on %s\n", server.Name, server.Addr)
		}
	}
}

func handleConfigDump(_ context.Context) {
	// Extract config path from os.Args (it was preserved for config subcommand)
	// os.Args format: [prog, --config, PATH, config, dump, FLAGS...]
	var configFile string
	var format string = "toml"
	var maskSecrets bool = true
	var flagsStartIndex int

	// Look for --config flag and find where "dump" ends
	skipNext := false
	for i := 1; i < len(os.Args); i++ {
		if skipNext {
			skipNext = false
			continue
		}
		if os.Args[i] == "--config" && i+1 < len(os.Args) {
			configFile = os.Args[i+1]
			skipNext = true
			continue
		}
		if os.Args[i] == "dump" {
			flagsStartIndex = i + 1
			break
		}
	}

	// Parse additional flags after the subcommand
	flagSet := flag.NewFlagSet("config-dump", flag.ExitOnError)
	flagSet.StringVar(&format, "format", "toml", "Output format: toml or json")
	flagSet.BoolVar(&maskSecrets, "mask-secrets", true, "Mask sensitive values (passwords, keys)")
	flagSet.Usage = func() {
		fmt.Printf(`Dump the parsed configuration for debugging

Usage:
  sora-admin --config PATH config dump [options]

Options:
  --format FORMAT      Output format: toml or json (default: toml)
  --mask-secrets       Mask sensitive values like passwords (default: true)

Examples:
  sora-admin --config sora.config.toml config dump
  sora-admin --config sora.config.toml config dump --format json --mask-secrets=false
`)
	}

	if flagsStartIndex > 0 && flagsStartIndex < len(os.Args) {
		flagSet.Parse(os.Args[flagsStartIndex:])
	}

	if configFile == "" {
		fmt.Printf("Error: --config is required\n\n")
		flagSet.Usage()
		os.Exit(1)
	}

	// Load full configuration
	cfg := config.NewDefaultConfig()
	if err := config.LoadConfigFromFile(configFile, &cfg); err != nil {
		logger.Fatalf("Failed to load config file: %v", err)
	}

	// Mask secrets if requested
	if maskSecrets {
		if cfg.Database.Write != nil {
			cfg.Database.Write.Password = "***MASKED***"
		}
		if cfg.Database.Read != nil {
			cfg.Database.Read.Password = "***MASKED***"
		}
		cfg.S3.AccessKey = "***MASKED***"
		cfg.S3.SecretKey = "***MASKED***"
		cfg.S3.EncryptionKey = "***MASKED***"
		cfg.TLS.CertFile = "***MASKED***"
		cfg.TLS.KeyFile = "***MASKED***"
		if cfg.TLS.LetsEncrypt != nil {
			cfg.TLS.LetsEncrypt.S3.AccessKey = "***MASKED***"
			cfg.TLS.LetsEncrypt.S3.SecretKey = "***MASKED***"
		}
		cfg.Cluster.SecretKey = "***MASKED***"
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
