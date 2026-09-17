package managesieve

import (
	"context"
	"slices"
	"testing"

	"github.com/migadu/sora/pkg/resilient"
)

// TestDefaultExtensions verifies that when no supported_extensions are configured,
// the default set is used: the one delivery (LMTP, the Admin API) compiles scripts
// with, so ManageSieve never accepts a script that delivery then cannot run.
// editheader is not in it.
func TestDefaultExtensions(t *testing.T) {
	// Create a minimal server with no supported_extensions configured
	options := ManageSieveServerOptions{
		SupportedExtensions: nil, // Explicitly set to nil (not configured)
		MaxScriptSize:       DefaultMaxScriptSize,
	}

	// Create server (we don't need a real database for this test)
	server, err := New(
		context.Background(),
		"test-server",
		"localhost",
		":0",                           // Use port 0 to let OS assign a free port
		&resilient.ResilientDatabase{}, // Minimal mock database
		options,
	)

	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	if !slices.Equal(server.supportedExtensions, DefaultEnabledExtensions) {
		t.Errorf("default extensions = %v, want delivery's default set %v", server.supportedExtensions, DefaultEnabledExtensions)
	}

	extensionMap := make(map[string]bool)
	for _, ext := range server.supportedExtensions {
		extensionMap[ext] = true
	}
	if extensionMap["editheader"] {
		t.Error("editheader is enabled by default; it must be opted into via [sieve] enabled_extensions")
	}

	// Verify all extensions listed in config.toml.example are present
	configExampleExtensions := []string{
		"fileinto",
		"envelope",
		"encoded-character",
		"imap4flags",
		"variables",
		"relational",
		"copy",
		"regex",
		"vacation",
		"comparator-i;octet",
		"comparator-i;ascii-casemap",
		"comparator-i;ascii-numeric",
		"comparator-i;unicode-casemap",
		"body",
	}

	for _, expectedExt := range configExampleExtensions {
		if !extensionMap[expectedExt] {
			t.Errorf("Extension %q from config.toml.example not found in default extensions", expectedExt)
		}
	}
}

// TestExplicitExtensions verifies that when supported_extensions are configured,
// only those extensions are used (no defaults applied).
func TestExplicitExtensions(t *testing.T) {
	// Create a server with explicit supported_extensions
	explicitExtensions := []string{"fileinto", "vacation"}
	options := ManageSieveServerOptions{
		SupportedExtensions: explicitExtensions,
		MaxScriptSize:       DefaultMaxScriptSize,
	}

	server, err := New(
		context.Background(),
		"test-server",
		"localhost",
		":0",
		&resilient.ResilientDatabase{},
		options,
	)

	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	// Verify that supportedExtensions contains only the explicitly configured extensions
	if len(server.supportedExtensions) != len(explicitExtensions) {
		t.Errorf("Expected %d extensions, got %d", len(explicitExtensions), len(server.supportedExtensions))
	}

	for i, ext := range server.supportedExtensions {
		if ext != explicitExtensions[i] {
			t.Errorf("Expected extension %q at index %d, got %q", explicitExtensions[i], i, ext)
		}
	}
}

// TestEmptyExtensionsArray verifies that when supported_extensions is an empty array,
// it's treated the same as not being configured (i.e., defaults are used).
func TestEmptyExtensionsArray(t *testing.T) {
	// Create a server with empty supported_extensions array
	options := ManageSieveServerOptions{
		SupportedExtensions: []string{}, // Empty array
		MaxScriptSize:       DefaultMaxScriptSize,
	}

	server, err := New(
		context.Background(),
		"test-server",
		"localhost",
		":0",
		&resilient.ResilientDatabase{},
		options,
	)

	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	if !slices.Equal(server.supportedExtensions, DefaultEnabledExtensions) {
		t.Errorf("default extensions for empty array = %v, want %v", server.supportedExtensions, DefaultEnabledExtensions)
	}
}
