//go:build linux || freebsd || darwin || openbsd || netbsd

package server

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/migadu/sora/logger"
	"golang.org/x/sys/unix"
)

// ListenWithBacklog creates a TCP listener with a custom listen backlog.
// Uses net.ListenConfig with a Control function to set socket options and backlog.
//
// Why this matters:
// - Small backlog (default SOMAXCONN = 128-512) causes SYN packets to be dropped when under load
// - Dropped SYN packets trigger TCP retransmissions with exponential backoff (1s, 3s, 6s, 12s, 24s...)
// - This leads to connection delays of ~60 seconds before clients can connect
// - Larger backlog (4096-8192) allows the kernel to queue more connections during bursts
//
// Implementation: Uses net.ListenConfig which properly handles all socket setup,
// and we only intervene to set SO_LISTENQLIMIT (FreeBSD) or adjust the backlog.
func ListenWithBacklog(ctx context.Context, network, address string, backlog int) (net.Listener, error) {
	// On FreeBSD, we can use SO_LISTENQLIMIT to set the listen backlog
	// This must be set BEFORE calling listen()
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var ctrlErr error
			err := c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR for fast restart
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					ctrlErr = fmt.Errorf("failed to set SO_REUSEADDR: %w", err)
					return
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
		// Handle zone ID for link-local addresses (fe80::)
		if addr.Zone != "" {
			if iface, err := net.InterfaceByName(addr.Zone); err == nil {
				sa.ZoneId = uint32(iface.Index)
			}
			return ctrlErr
		},
	}

	listener, err := lc.Listen(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	return listener, nil
}