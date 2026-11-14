package main

// connections.go - Command handlers for connections
// Extracted from main.go for better organization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
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
	domain := fs.String("domain", "", "Filter connections by domain")
	protocol := fs.String("protocol", "", "Filter connections by protocol (IMAP, POP3, LMTP)")
	instanceID := fs.String("instance", "", "Filter connections by instance ID")

	fs.Usage = func() {
		fmt.Printf(`List active proxy connections

Usage:
  sora-admin connections list [options]

Options:
  --user string         Filter connections by user email
  --domain string       Filter connections by domain
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
  sora-admin --config config.toml connections list --domain example.com
  sora-admin --config config.toml connections list --protocol IMAP
  sora-admin --config config.toml connections list --instance server1
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// List connections
	if err := listConnections(ctx, globalConfig, *userEmail, *domain, *protocol, *instanceID); err != nil {
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
	confirm := fs.Bool("confirm", false, "Skip confirmation prompt")
	yes := fs.Bool("y", false, "Skip confirmation prompt (alias for --confirm)")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`Force disconnect proxy connections via gossip protocol

Usage:
  sora-admin connections kick [options]

Options:
  --user string         Kick all connections for specific user email (REQUIRED)
  --protocol string     Kick connections using specific protocol (IMAP, POP3, ManageSieve)
  --confirm             Skip confirmation prompt
  -y                    Skip confirmation prompt (alias for --confirm)

This command uses the HTTP API to broadcast a kick event via the gossip protocol.
All cluster nodes will receive the kick and terminate matching connections within ~100ms.

Configuration Requirements:
  - [admin_cli] addr must be set in config (e.g., "http://localhost:8080")
  - [admin_cli] api_key must be set in config

Examples:
  sora-admin --config config.toml connections kick --user user@example.com
  sora-admin --config config.toml connections kick --user user@example.com --protocol IMAP
  sora-admin --config config.toml connections kick --user user@example.com --confirm
  sora-admin --config config.toml connections kick --user user@example.com -y
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
	autoConfirm := *yes || *confirm
	if err := kickConnections(ctx, globalConfig, *userEmail, *protocol, *server, *clientAddr, *all, autoConfirm); err != nil {
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

Note: This command calls the Admin API named by [admin_cli]. The affinity will be gossiped
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

	// Call admin API
	reqBody := map[string]string{
		"user":     *userEmail,
		"protocol": *protocol,
		"backend":  *backendAddr,
	}

	var resp struct {
		Message string `json:"message"`
	}
	if err := callAdminAPI(ctx, globalConfig, "POST", "/admin/affinity", nil, reqBody, &resp); err != nil {
		logger.Fatalf("Failed to set affinity: %v", err)
	}

	fmt.Printf("[OK] Affinity set successfully and gossiped to cluster\n")
	fmt.Printf("  User: %s\n", *userEmail)
	fmt.Printf("  Protocol: %s\n", *protocol)
	fmt.Printf("  Backend: %s\n", *backendAddr)
	if resp.Message != "" {
		fmt.Printf("  %s\n", resp.Message)
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

	// The Admin API answers 200 with the backend, or 404 when the user has no affinity.
	var resp struct {
		Backend string `json:"backend"`
	}
	query := url.Values{"user": {*userEmail}, "protocol": {*protocol}}
	err := callAdminAPI(ctx, globalConfig, "GET", "/admin/affinity", query, nil, &resp)
	var apiErr *adminAPIStatusError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		fmt.Printf("No affinity found for user %s and protocol %s\n", *userEmail, *protocol)
		return
	}
	if err != nil {
		logger.Fatalf("Failed to get affinity: %v", err)
	}

	fmt.Printf("Affinity for %s (%s):\n", *userEmail, *protocol)
	fmt.Printf("  Backend: %s\n", resp.Backend)
}

func handleListAffinity(ctx context.Context) {
	fs := flag.NewFlagSet("affinity list", flag.ExitOnError)

	protocol := fs.String("protocol", "", "Only affinities of this protocol")
	backendAddr := fs.String("backend", "", "Only affinities to this backend server address")

	fs.Usage = func() {
		fmt.Printf(`List backend server affinities

Usage:
  sora-admin affinity list [options]

Options:
  --config string    Path to TOML configuration file (required)
  --protocol string  Only affinities of this protocol, e.g. imap
  --backend string   Only affinities to this backend server address, e.g. 192.168.1.10:993

Note: This command lists the affinities held by the node whose Admin API [admin_cli]
      names. Every node applies the affinities the others gossip, so each node of a
      converged cluster holds the same set.

Examples:
  sora-admin affinity list --config config.toml
  sora-admin affinity list --config config.toml --backend 192.168.1.10:993
`)
	}

	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	query := url.Values{}
	if *protocol != "" {
		query.Set("protocol", strings.ToLower(*protocol))
	}
	if *backendAddr != "" {
		query.Set("backend", *backendAddr)
	}

	var resp struct {
		Affinities []struct {
			User      string    `json:"user"`
			Protocol  string    `json:"protocol"`
			Backend   string    `json:"backend"`
			ExpiresAt time.Time `json:"expires_at"`
			NodeID    string    `json:"node_id"`
		} `json:"affinities"`
	}
	if err := callAdminAPI(ctx, globalConfig, "GET", "/admin/affinity/list", query, nil, &resp); err != nil {
		logger.Fatalf("Failed to list affinities: %v", err)
	}

	if len(resp.Affinities) == 0 {
		fmt.Println("No affinities found.")
		return
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "User\tProtocol\tBackend\tExpires\tAssigned by")
	for _, a := range resp.Affinities {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", a.User, a.Protocol, a.Backend, a.ExpiresAt.Format(time.RFC3339), a.NodeID)
	}
	tw.Flush()
	fmt.Printf("\nTotal: %d\n", len(resp.Affinities))
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

Note: This command calls the Admin API named by [admin_cli]. The deletion will be gossiped
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

	var resp struct {
		Message string `json:"message"`
	}
	query := url.Values{"user": {*userEmail}, "protocol": {*protocol}}
	if err := callAdminAPI(ctx, globalConfig, "DELETE", "/admin/affinity", query, nil, &resp); err != nil {
		logger.Fatalf("Failed to delete affinity: %v", err)
	}

	fmt.Printf("[OK] Affinity deleted successfully and gossiped to cluster\n")
	fmt.Printf("  User: %s\n", *userEmail)
	fmt.Printf("  Protocol: %s\n", *protocol)
	if resp.Message != "" {
		fmt.Printf("  %s\n", resp.Message)
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
  list     List backend affinities, optionally of one protocol or backend
  delete   Remove backend affinity for a user (gossiped to all nodes)
  help     Show this help message

Note: Affinity is managed via the cluster gossip protocol. Changes are automatically
      propagated to all nodes. The commands call the Admin API named by [admin_cli]
      (addr, api_key, insecure_skip_verify).

Examples:
  sora-admin affinity set --config config.toml --user user@example.com --protocol imap --backend 192.168.1.10:993
  sora-admin affinity get --config config.toml --user user@example.com --protocol imap
  sora-admin affinity list --config config.toml --backend 192.168.1.10:993
  sora-admin affinity delete --config config.toml --user user@example.com --protocol imap

Use 'sora-admin affinity <subcommand> --help' for detailed help.
`)
}

// trackerInstance returns what follows the protocol in the key the Admin API
// reports a tracker under: "<node_id>-<listener>" for a proxy, the listener
// name for a backend. Node IDs and listener names both contain dashes
// ("node-1", "imap-proxy"), so the key is cut after the protocol only.
func trackerInstance(key string) string {
	if _, instance, ok := strings.Cut(key, "-"); ok {
		return instance
	}
	return key
}

func listConnections(ctx context.Context, cfg AdminConfig, userEmail, domain, protocol, instanceID string) error {
	// Create HTTP API client
	client, err := createHTTPAPIClient(cfg)
	if err != nil {
		return fmt.Errorf("failed to create HTTP API client: %w", err)
	}

	// Build URL based on whether user email is specified
	var endpoint string
	if userEmail != "" {
		// One path segment: a "/" in the local part goes as %2F (RFC 3986 §2.2).
		endpoint = fmt.Sprintf("%s/admin/connections/user/%s", cfg.HTTPAPIAddr, url.PathEscape(userEmail))
	} else {
		endpoint = fmt.Sprintf("%s/admin/connections", cfg.HTTPAPIAddr)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
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
			Instance   string    `json:"instance"` // Full tracker key (for filtering/debugging)
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

	// Apply filters (domain, protocol and instanceID are client-side filters)
	filteredConnections := result.Connections
	if domain != "" || protocol != "" || instanceID != "" {
		filtered := make([]struct {
			Protocol   string    `json:"protocol"`
			Instance   string    `json:"instance"`
			AccountID  int64     `json:"account_id"`
			Email      string    `json:"email"`
			LocalCount int       `json:"local_count"`
			TotalCount int       `json:"total_count"`
			LastUpdate time.Time `json:"last_update"`
		}, 0)
		for _, conn := range result.Connections {
			// Filter by domain (extract domain from email)
			if domain != "" {
				emailDomain := ""
				if idx := strings.Index(conn.Email, "@"); idx != -1 {
					emailDomain = conn.Email[idx+1:]
				}
				if !strings.EqualFold(emailDomain, domain) {
					continue
				}
			}
			// Filter by protocol using the instance field (full tracker key)
			// Examples: "LMTP" matches "LMTP-host1-proxy", "LMTP-host2-proxy", etc.
			//           "LMTP-host1" matches "LMTP-host1-proxy", "LMTP-host1-other", etc.
			//           "LMTP-host1-proxy" matches only "LMTP-host1-proxy"
			if protocol != "" {
				// Try exact match first (case-insensitive)
				exactMatch := strings.EqualFold(conn.Instance, protocol)
				// Try prefix match (case-insensitive)
				prefixMatch := strings.HasPrefix(strings.ToUpper(conn.Instance), strings.ToUpper(protocol)+"-")

				if !exactMatch && !prefixMatch {
					continue
				}
			}
			// instanceID is now supported via the instance field
			if instanceID != "" {
				if !strings.Contains(strings.ToLower(conn.Instance), strings.ToLower(instanceID)) {
					continue
				}
			}
			filtered = append(filtered, conn)
		}
		filteredConnections = filtered
	}

	if len(filteredConnections) == 0 {
		fmt.Println("No connections matching the specified filters.")
		return nil
	}

	// Display results header
	if userEmail != "" {
		fmt.Printf("Active connections for user: %s\n\n", userEmail)
	}

	// Print header
	fmt.Printf("%-25s %-12s %-30s %-12s %-12s %-20s\n",
		"User", "Protocol", "Instance", "Local", "Remote", "Last Update")
	fmt.Printf("%-25s %-12s %-30s %-12s %-12s %-20s\n",
		"----", "--------", "--------", "-----", "------", "-----------")

	// Print connection details. Each row is an account on one tracker, so the totals are
	// the sums of its Local and Remote columns, not the number of rows.
	totalLocal, totalRemote := 0, 0
	for _, conn := range filteredConnections {
		email := conn.Email
		if email == "" {
			email = fmt.Sprintf("account-%d", conn.AccountID)
		}

		// Truncate long emails
		if len(email) > 24 {
			email = email[:21] + "..."
		}

		instance := trackerInstance(conn.Instance)

		// Truncate if still too long
		if len(instance) > 29 {
			instance = instance[:26] + "..."
		}

		// Calculate remote count (Total - Local)
		remoteCount := conn.TotalCount - conn.LocalCount
		totalLocal += conn.LocalCount
		totalRemote += remoteCount

		fmt.Printf("%-25s %-12s %-30s %-12d %-12d %-20s\n",
			email,
			conn.Protocol,
			instance,
			conn.LocalCount,
			remoteCount,
			conn.LastUpdate.Format("2006-01-02 15:04:05"))
	}

	fmt.Printf("\nTotal connections: %d local, %d remote\n", totalLocal, totalRemote)
	if result.Source != "" {
		fmt.Printf("Source: %s\n", result.Source)
	}

	return nil
}

func kickConnections(ctx context.Context, cfg AdminConfig, userEmail, protocol, serverAddr, clientAddr string, all, autoConfirm bool) error {
	// Gossip-based kick requires user email (we need accountID)
	if userEmail == "" && !all {
		return fmt.Errorf("--user is required for gossip-based kick")
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

	fmt.Printf("\n[OK] %s\n", result["message"])
	if protocols, ok := result["protocols"].([]any); ok {
		fmt.Printf("   Protocols: %v\n", protocols)
	}
	if note, ok := result["note"].(string); ok {
		fmt.Printf("   %s\n", note)
	}

	return nil
}

// adminAPIStatusError is an Admin API answer other than 200 OK.
type adminAPIStatusError struct {
	StatusCode int
	Body       string
}

func (e *adminAPIStatusError) Error() string {
	return fmt.Sprintf("API returned status %d: %s", e.StatusCode, e.Body)
}

// callAdminAPI sends a request to the Admin API that [admin_cli] names, with its API key
// and TLS settings like every other HTTP command, and decodes the JSON answer into out.
// query is encoded into the URL (an address may hold "+", "&" or "#"). An answer other
// than 200 OK is an *adminAPIStatusError.
func callAdminAPI(ctx context.Context, cfg AdminConfig, method, path string, query url.Values, body, out any) error {
	client, err := createHTTPAPIClient(cfg)
	if err != nil {
		return err
	}

	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonData)
	}

	endpoint := cfg.HTTPAPIAddr + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+cfg.HTTPAPIKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return &adminAPIStatusError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(respBody))}
	}

	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	return nil
}
