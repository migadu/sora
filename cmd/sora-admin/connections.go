package main

// connections.go - Command handlers for connections
// Extracted from main.go for better organization

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/migadu/sora/logger"
)

func handleConnectionsCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printConnectionsUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "list":
		handleListConnections(ctx)
	case "kick":
		handleKickConnections(ctx)
	case "help", "--help", "-h":
		printConnectionsUsage()
	default:
		fmt.Printf("Unknown connections subcommand: %s\n\n", subcommand)
		printConnectionsUsage()
		os.Exit(1)
	}
}

func handleListConnections(ctx context.Context) {
	// Parse connections list specific flags
	fs := flag.NewFlagSet("connections list", flag.ExitOnError)

	userEmail := fs.String("user", "", "Filter connections by user email")
	protocol := fs.String("protocol", "", "Filter connections by protocol (IMAP, POP3, LMTP)")
	instanceID := fs.String("instance", "", "Filter connections by instance ID")

	fs.Usage = func() {
		fmt.Printf(`List active proxy connections

Usage:
  sora-admin connections list [options]

Options:
  --user string         Filter connections by user email
  --protocol string     Filter connections by protocol (IMAP, POP3, LMTP)
  --instance string     Filter connections by instance ID

This command shows:
  - Active connections with client and server addresses
  - Protocol type and connection duration
  - User email and instance information
  - Connection activity status

Examples:
  sora-admin --config config.toml connections list
  sora-admin --config config.toml connections list --user user@example.com
  sora-admin --config config.toml connections list --protocol IMAP
  sora-admin --config config.toml connections list --instance server1
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// List connections
	if err := listConnections(ctx, globalConfig, *userEmail, *protocol, *instanceID); err != nil {
		logger.Fatalf("Failed to list connections: %v", err)
	}
}

func handleKickConnections(ctx context.Context) {
	// Parse kick-connections specific flags
	fs := flag.NewFlagSet("connections kick", flag.ExitOnError)

	userEmail := fs.String("user", "", "Kick all connections for specific user email")
	protocol := fs.String("protocol", "", "Kick connections using specific protocol (IMAP, POP3, ManageSieve)")
	server := fs.String("server", "", "Kick connections to specific server")
	clientAddr := fs.String("client", "", "Kick connection from specific client address")
	all := fs.Bool("all", false, "Kick all active connections")
	confirm := fs.Bool("confirm", false, "Confirm kick without interactive prompt")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`Force disconnect proxy connections via gossip protocol

Usage:
  sora-admin connections kick [options]

Options:
  --user string         Kick all connections for specific user email (REQUIRED)
  --protocol string     Kick connections using specific protocol (IMAP, POP3, ManageSieve)
  --confirm             Confirm kick without interactive prompt

This command uses the HTTP API to broadcast a kick event via the gossip protocol.
All cluster nodes will receive the kick and terminate matching connections within ~100ms.

Configuration Requirements:
  - http_api_addr must be set in config (e.g., "http://localhost:8080")
  - http_api_key must be set in config

Examples:
  sora-admin --config config.toml connections kick --user user@example.com
  sora-admin --config config.toml connections kick --user user@example.com --protocol IMAP
  sora-admin --config config.toml connections kick --user user@example.com --confirm
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate that at least one filter is specified
	if *userEmail == "" && *protocol == "" && *server == "" && *clientAddr == "" && !*all {
		fmt.Printf("Error: At least one filtering option must be specified\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Validate protocol if specified
	if *protocol != "" {
		validProtocols := []string{"IMAP", "POP3", "ManageSieve"}
		valid := false
		for _, p := range validProtocols {
			if strings.EqualFold(*protocol, p) {
				valid = true
				*protocol = p // Normalize case
				break
			}
		}
		if !valid {
			fmt.Printf("Error: Invalid protocol. Must be one of: %s\n\n", strings.Join(validProtocols, ", "))
			fs.Usage()
			os.Exit(1)
		}
	}

	// Kick connections
	if err := kickConnections(ctx, globalConfig, *userEmail, *protocol, *server, *clientAddr, *all, *confirm); err != nil {
		logger.Fatalf("Failed to kick connections: %v", err)
	}
}

func handleAffinityCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printAffinityUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "set":
		handleSetAffinity(ctx)
	case "get":
		handleGetAffinity(ctx)
	case "list":
		handleListAffinity(ctx)
	case "delete":
		handleDeleteAffinity(ctx)
	case "help", "--help", "-h":
		printAffinityUsage()
	default:
		fmt.Printf("Unknown affinity subcommand: %s\n\n", subcommand)
		printAffinityUsage()
		os.Exit(1)
	}
}

func handleSetAffinity(ctx context.Context) {
	fs := flag.NewFlagSet("affinity set", flag.ExitOnError)

	userEmail := fs.String("user", "", "User email address (required)")
	protocol := fs.String("protocol", "", "Protocol: imap, pop3, or managesieve (required)")
	backendAddr := fs.String("backend", "", "Backend server address, e.g., 192.168.1.10:993 (required)")

	fs.Usage = func() {
		fmt.Printf(`Set backend server affinity for a user

Usage:
  sora-admin affinity set [options]

Options:
  --config string    Path to TOML configuration file (required)
  --user string      User email address (required)
  --protocol string  Protocol: imap, pop3, or managesieve (required)
  --backend string   Backend server address, e.g., 192.168.1.10:993 (required)

Note: This command calls the admin API HTTP endpoint. The affinity will be gossiped
      to all nodes in the cluster automatically.

Examples:
  sora-admin affinity set --config config.toml --user user@example.com --protocol imap --backend 192.168.1.10:993
`)
	}

	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *userEmail == "" || *protocol == "" || *backendAddr == "" {
		fmt.Printf("Error: --user, --protocol, and --backend are required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Validate protocol
	validProtocols := map[string]bool{"imap": true, "pop3": true, "managesieve": true}
	*protocol = strings.ToLower(*protocol)
	if !validProtocols[*protocol] {
		fmt.Printf("Error: protocol must be one of: imap, pop3, managesieve\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Find admin API server config
	var adminAPIAddr, adminAPIKey string
	for _, server := range globalConfig.DynamicServers {
		if server.Type == "http_admin_api" {
			adminAPIAddr = server.Addr
			adminAPIKey = server.APIKey
			break
		}
	}

	if adminAPIAddr == "" {
		logger.Fatalf("No http_admin_api server found in config")
	}
	if adminAPIKey == "" {
		logger.Fatalf("Admin API server found but missing api_key in config")
	}

	// Call admin API
	reqBody := map[string]string{
		"user":     *userEmail,
		"protocol": *protocol,
		"backend":  *backendAddr,
	}

	respData, err := callAdminAPI(ctx, adminAPIAddr, adminAPIKey, "POST", "/admin/affinity", reqBody)
	if err != nil {
		logger.Fatalf("Failed to set affinity: %v", err)
	}

	fmt.Printf("✓ Affinity set successfully and gossiped to cluster\n")
	fmt.Printf("  User: %s\n", *userEmail)
	fmt.Printf("  Protocol: %s\n", *protocol)
	fmt.Printf("  Backend: %s\n", *backendAddr)
	if msg, ok := respData["message"].(string); ok {
		fmt.Printf("  %s\n", msg)
	}
}

func handleGetAffinity(ctx context.Context) {
	fs := flag.NewFlagSet("affinity get", flag.ExitOnError)

	userEmail := fs.String("user", "", "User email address (required)")
	protocol := fs.String("protocol", "", "Protocol: imap, pop3, or managesieve (required)")

	fs.Usage = func() {
		fmt.Printf(`Get backend server affinity for a user

Usage:
  sora-admin affinity get [options]

Options:
  --config string    Path to TOML configuration file (required)
  --user string      User email address (required)
  --protocol string  Protocol: imap, pop3, or managesieve (required)

Examples:
  sora-admin affinity get --config config.toml --user user@example.com --protocol imap
`)
	}

	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *userEmail == "" || *protocol == "" {
		fmt.Printf("Error: --user, and --protocol are required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	*protocol = strings.ToLower(*protocol)

	// Find admin API server config
	var adminAPIAddr, adminAPIKey string
	for _, server := range globalConfig.DynamicServers {
		if server.Type == "http_admin_api" {
			adminAPIAddr = server.Addr
			adminAPIKey = server.APIKey
			break
		}
	}

	if adminAPIAddr == "" {
		logger.Fatalf("No http_admin_api server found in config")
	}
	if adminAPIKey == "" {
		logger.Fatalf("Admin API server found but missing api_key in config")
	}

	// Call admin API
	url := fmt.Sprintf("/admin/affinity?user=%s&protocol=%s", *userEmail, *protocol)
	respData, err := callAdminAPI(ctx, adminAPIAddr, adminAPIKey, "GET", url, nil)
	if err != nil {
		logger.Fatalf("Failed to get affinity: %v", err)
	}

	found, _ := respData["found"].(bool)
	if !found {
		fmt.Printf("No affinity found for user %s and protocol %s\n", *userEmail, *protocol)
		return
	}

	backend, _ := respData["backend"].(string)
	fmt.Printf("Affinity for %s (%s):\n", *userEmail, *protocol)
	fmt.Printf("  Backend: %s\n", backend)
}

func handleListAffinity(_ context.Context) {
	fmt.Println("List operation not yet supported - affinities are distributed via gossip.")
	fmt.Println("Use 'get' with specific user/protocol to check individual affinities.")
}

func handleDeleteAffinity(ctx context.Context) {
	fs := flag.NewFlagSet("affinity delete", flag.ExitOnError)

	userEmail := fs.String("user", "", "User email address (required)")
	protocol := fs.String("protocol", "", "Protocol: imap, pop3, or managesieve (required)")

	fs.Usage = func() {
		fmt.Printf(`Delete backend server affinity for a user

Usage:
  sora-admin affinity delete [options]

Options:
  --config string    Path to TOML configuration file (required)
  --user string      User email address (required)
  --protocol string  Protocol: imap, pop3, or managesieve (required)

Note: This command calls the admin API HTTP endpoint. The deletion will be gossiped
      to all nodes in the cluster automatically.

Examples:
  sora-admin affinity delete --config config.toml --user user@example.com --protocol imap
`)
	}

	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *userEmail == "" || *protocol == "" {
		fmt.Printf("Error: --user, and --protocol are required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	*protocol = strings.ToLower(*protocol)

	// Find admin API server config
	var adminAPIAddr, adminAPIKey string
	for _, server := range globalConfig.DynamicServers {
		if server.Type == "http_admin_api" {
			adminAPIAddr = server.Addr
			adminAPIKey = server.APIKey
			break
		}
	}

	if adminAPIAddr == "" {
		logger.Fatalf("No http_admin_api server found in config")
	}
	if adminAPIKey == "" {
		logger.Fatalf("Admin API server found but missing api_key in config")
	}

	// Call admin API
	url := fmt.Sprintf("/admin/affinity?user=%s&protocol=%s", *userEmail, *protocol)
	respData, err := callAdminAPI(ctx, adminAPIAddr, adminAPIKey, "DELETE", url, nil)
	if err != nil {
		logger.Fatalf("Failed to delete affinity: %v", err)
	}

	fmt.Printf("✓ Affinity deleted successfully and gossiped to cluster\n")
	fmt.Printf("  User: %s\n", *userEmail)
	fmt.Printf("  Protocol: %s\n", *protocol)
	if msg, ok := respData["message"].(string); ok {
		fmt.Printf("  %s\n", msg)
	}
}

func printConnectionsUsage() {
	fmt.Printf(`Connection Management

Usage:
  sora-admin connections <subcommand> [options]

Subcommands:
  list   List active proxy connections
  kick   Force disconnect proxy connections

Examples:
  sora-admin connections list
  sora-admin connections list --user user@example.com
  sora-admin connections kick --user user@example.com
  sora-admin connections kick --all

Use 'sora-admin connections <subcommand> --help' for detailed help.
`)
}

func printAffinityUsage() {
	fmt.Printf(`Manage user-to-backend affinity mappings (via gossip)

Usage:
  sora-admin affinity <subcommand> [options]

Subcommands:
  set      Set backend affinity for a user (gossiped to all nodes)
  get      Get backend affinity for a user
  delete   Remove backend affinity for a user (gossiped to all nodes)
  help     Show this help message

Note: Affinity is managed via the cluster gossip protocol. Changes are automatically
      propagated to all nodes. The admin API must be enabled in your config.

Examples:
  sora-admin affinity set --config config.toml --user user@example.com --protocol imap --backend 192.168.1.10:993
  sora-admin affinity get --config config.toml --user user@example.com --protocol imap
  sora-admin affinity delete --config config.toml --user user@example.com --protocol imap

Use 'sora-admin affinity <subcommand> --help' for detailed help.
`)
}

func listConnections(ctx context.Context, cfg AdminConfig, userEmail, protocol, instanceID string) error {
	// Create HTTP API client
	client, err := createHTTPAPIClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create HTTP API client: %w", err)
	}

	// Build URL based on whether user email is specified
	var url string
	if userEmail != "" {
		url = fmt.Sprintf("%s/admin/connections/user/%s", cfg.HTTPAPIAddr, userEmail)
	} else {
		url = fmt.Sprintf("%s/admin/connections", cfg.HTTPAPIAddr)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+cfg.HTTPAPIKey)

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to get connections: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var result struct {
		Connections []struct {
			Protocol   string    `json:"protocol"`
			AccountID  int64     `json:"account_id"`
			Email      string    `json:"email"`
			LocalCount int       `json:"local_count"`
			TotalCount int       `json:"total_count"`
			LastUpdate time.Time `json:"last_update"`
		} `json:"connections"`
		Count  int    `json:"count"`
		Source string `json:"source,omitempty"`
		Note   string `json:"note,omitempty"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Display note if present (e.g., tracking not available)
	if result.Note != "" {
		fmt.Printf("Note: %s\n\n", result.Note)
	}

	// Check if no connections found
	if result.Count == 0 {
		if userEmail != "" {
			fmt.Printf("No active connections found for user: %s\n", userEmail)
		} else {
			fmt.Println("No active connections found.")
		}
		return nil
	}

	// Display results
	if userEmail != "" {
		fmt.Printf("Active connections for user: %s\n\n", userEmail)
	} else {
		fmt.Printf("Found %d active connection(s):\n\n", result.Count)
	}

	// Apply filters (protocol and instanceID are client-side filters)
	filteredConnections := result.Connections
	if protocol != "" || instanceID != "" {
		filtered := make([]struct {
			Protocol   string    `json:"protocol"`
			AccountID  int64     `json:"account_id"`
			Email      string    `json:"email"`
			LocalCount int       `json:"local_count"`
			TotalCount int       `json:"total_count"`
			LastUpdate time.Time `json:"last_update"`
		}, 0)
		for _, conn := range result.Connections {
			// Filter by protocol (supports both exact match and prefix match)
			// Examples: "LMTP" matches "LMTP-proxy1", "LMTP-proxy2", etc.
			//           "LMTP-proxy1" matches only "LMTP-proxy1"
			if protocol != "" {
				// Try exact match first (case-insensitive)
				exactMatch := strings.EqualFold(conn.Protocol, protocol)
				// Try prefix match (case-insensitive)
				prefixMatch := strings.HasPrefix(strings.ToUpper(conn.Protocol), strings.ToUpper(protocol)+"-")

				if !exactMatch && !prefixMatch {
					continue
				}
			}
			// Note: instanceID filtering not available with gossip tracking
			if instanceID != "" {
				fmt.Println("Warning: --instance filtering not available with gossip-based tracking")
			}
			filtered = append(filtered, conn)
		}
		filteredConnections = filtered
	}

	if len(filteredConnections) == 0 {
		fmt.Println("No connections matching the specified filters.")
		return nil
	}

	// Print header
	fmt.Printf("%-25s %-12s %-12s %-12s %-20s\n",
		"User", "Protocol", "Local", "Total", "Last Update")
	fmt.Printf("%-25s %-12s %-12s %-12s %-20s\n",
		"----", "--------", "-----", "-----", "-----------")

	// Print connection details
	for _, conn := range filteredConnections {
		email := conn.Email
		if email == "" {
			email = fmt.Sprintf("account-%d", conn.AccountID)
		}

		// Truncate long emails
		if len(email) > 24 {
			email = email[:21] + "..."
		}

		fmt.Printf("%-25s %-12s %-12d %-12d %-20s\n",
			email,
			conn.Protocol,
			conn.LocalCount,
			conn.TotalCount,
			conn.LastUpdate.Format("2006-01-02 15:04:05"))
	}

	fmt.Printf("\nTotal connections: %d\n", len(filteredConnections))
	if result.Source != "" {
		fmt.Printf("Source: %s\n", result.Source)
	}

	return nil
}

func kickConnections(ctx context.Context, cfg AdminConfig, userEmail, protocol, serverAddr, clientAddr string, all, autoConfirm bool) error {
	// Gossip-based kick requires user email (we need accountID)
	if userEmail == "" && !all {
		return fmt.Errorf("--user is required for gossip-based kick (or use --all)")
	}

	// serverAddr and clientAddr filtering not supported with gossip
	if serverAddr != "" || clientAddr != "" {
		return fmt.Errorf("--server and --client filtering not supported with gossip-based tracking")
	}

	if all {
		return fmt.Errorf("--all not yet implemented for gossip-based tracking (kick users individually)")
	}

	// Confirm if not auto-confirmed
	if !autoConfirm {
		fmt.Printf("Kick user %s", userEmail)
		if protocol != "" {
			fmt.Printf(" from protocol %s", protocol)
		} else {
			fmt.Printf(" from all protocols")
		}
		fmt.Printf("? (y/N): ")

		var response string
		if _, err := fmt.Scanln(&response); err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("Operation cancelled.")
			return nil
		}
	}

	// Use HTTP API to kick via gossip
	client, err := createHTTPAPIClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create HTTP API client: %w", err)
	}

	reqBody := map[string]string{
		"user_email": userEmail,
	}
	if protocol != "" {
		reqBody["protocol"] = protocol
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/admin/connections/kick", cfg.HTTPAPIAddr)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.HTTPAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send kick request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kick failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	fmt.Printf("\n✅ %s\n", result["message"])
	if protocols, ok := result["protocols"].([]any); ok {
		fmt.Printf("   Protocols: %v\n", protocols)
	}
	if note, ok := result["note"].(string); ok {
		fmt.Printf("   %s\n", note)
	}

	return nil
}

func callAdminAPI(ctx context.Context, addr, apiKey, method, path string, body any) (map[string]any, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	// Build URL - ensure addr has scheme
	url := addr
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	url = url + path

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}
