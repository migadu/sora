//go:build linux || freebsd || darwin || openbsd || netbsd

package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// ListenWithBacklog creates a TCP listener with a custom listen backlog.
// This manually creates the socket to have full control over the listen() syscall.
//
// Why this matters:
// - Small backlog (default SOMAXCONN = 128-512) causes SYN packets to be dropped when under load
// - Dropped SYN packets trigger TCP retransmissions with exponential backoff (1s, 3s, 6s, 12s, 24s...)
// - This leads to connection delays of ~60 seconds before clients can connect
// - Larger backlog (4096-8192) allows the kernel to queue more connections during bursts
//
// The process:
// 1. Create socket
// 2. Set SO_REUSEADDR for fast restart
// 3. Bind socket to address
// 4. Call listen() with custom backlog
// 5. Create net.Listener from file descriptor
func ListenWithBacklog(ctx context.Context, network, address string, backlog int) (net.Listener, error) {
	// Resolve the address
	addr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	// Determine address family
	var family int
	var sockaddr unix.Sockaddr

	// Handle nil IP (e.g., ":143" resolves to IP=nil)
	// Default to IPv4 for backward compatibility
	if addr.IP == nil || addr.IP.To4() != nil {
		family = unix.AF_INET
		sa := &unix.SockaddrInet4{Port: addr.Port}
		if addr.IP != nil {
			copy(sa.Addr[:], addr.IP.To4())
		}
		// If IP is nil, sa.Addr is zero (0.0.0.0), which means all interfaces
		sockaddr = sa
	} else {
		family = unix.AF_INET6
		sa := &unix.SockaddrInet6{Port: addr.Port}
		copy(sa.Addr[:], addr.IP.To16())
		sockaddr = sa
	}

	// Create socket
	fd, err := unix.Socket(family, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	// Set SO_REUSEADDR to allow fast restart
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set SO_REUSEADDR: %w", err)
	}

	// Bind socket
	if err := unix.Bind(fd, sockaddr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to bind socket: %w", err)
	}

	// Listen with custom backlog
	if err := unix.Listen(fd, backlog); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	// Create net.Listener from file descriptor
	file := os.NewFile(uintptr(fd), "listener")
	listener, err := net.FileListener(file)
	file.Close() // FileListener dups the fd, so we can close the file
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	return listener, nil
}

// MakeListenControl creates a Control function for net.ListenConfig that sets socket options.
// This is kept for compatibility but doesn't set the backlog (use ListenWithBacklog for that).
func MakeListenControl(backlog int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		// This function is no longer used for setting backlog.
		// Use ListenWithBacklog instead for proper backlog control.
		return nil
	}
}
