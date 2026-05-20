package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/adminapi"
)

func TestAdminAPIConnections_StorageNodeIntegration(t *testing.T) {
	deps := &serverDependencies{
		connectionTrackers: make(map[string]*server.ConnectionTracker),
	}

	// Create a tracker for IMAP backend (snapshotOnly=true)
	// This simulates the fix for storage node tracking
	tracker := server.NewConnectionTracker("IMAP", "main", "localhost", "localhost-main", nil, 0, 0, 0, true)
	if tracker == nil {
		t.Fatal("NewConnectionTracker returned nil")
	}
	deps.connectionTrackers["IMAP-main"] = tracker

	// Register an active connection
	ctx := context.Background()
	err := tracker.RegisterConnection(ctx, 123, "user@example.com", "IMAP", "192.168.1.1:12345")
	if err != nil {
		t.Fatalf("Failed to register connection: %v", err)
	}

	// Start Admin API Server
	errChan := make(chan error, 1)
	opts := adminapi.ServerOptions{
		Addr:               "127.0.0.1:0", // random port
		APIKey:             "test-key",
		ConnectionTrackers: deps.connectionTrackers,
	}
	// adminapi.Start will bind and listen in background
	_ = adminapi.Start(ctx, nil, opts, errChan)

	// Wait for server to start up
	time.Sleep(100 * time.Millisecond)

	// Since we don't know the port, we can't easily make a request if we don't have a way to get the port
	// Wait, we need to get the bound port, but adminapi doesn't expose it.
	// So instead of starting, we can use an exported function?
	// If there is no exported router, we must use a fixed port for this test
	opts.Addr = "127.0.0.1:29091"
	_ = adminapi.Start(ctx, nil, opts, errChan)
	time.Sleep(100 * time.Millisecond)

	// Make request to list connections
	req, _ := http.NewRequest("GET", "http://127.0.0.1:29091/admin/connections", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	client := &http.Client{Timeout: time.Second}
	respObj, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer respObj.Body.Close()

	if respObj.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", respObj.StatusCode)
	}

	// Decode response
	var resp struct {
		Count       int              `json:"count"`
		Connections []map[string]any `json:"connections"`
		Note        string           `json:"note"`
	}
	if err := json.NewDecoder(respObj.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify we got 1 connection
	if resp.Count != 1 {
		t.Errorf("Expected 1 connection, got %d. Note: %s", resp.Count, resp.Note)
	}

	if len(resp.Connections) != 1 {
		t.Errorf("Expected 1 connection details, got %d", len(resp.Connections))
	} else {
		conn := resp.Connections[0]
		if conn["email"] != "user@example.com" {
			t.Errorf("Expected email user@example.com, got %v", conn["email"])
		}
		if conn["protocol"] != "IMAP" {
			t.Errorf("Expected protocol IMAP, got %v", conn["protocol"])
		}
	}
}
