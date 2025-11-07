//go:build dragonfly || freebsd || linux || netbsd || openbsd

package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
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

	// Determine address family and socket options
	var family int
	var sockaddr unix.Sockaddr
	var ipv6only int = 1 // Default: IPv6-only for explicit IPv6 addresses

	// Handle nil IP (e.g., ":143" resolves to IP=nil)
	// Use IPv6 dual-stack for wildcard to accept both IPv4 and IPv6 (matches Go's net.Listen)
	if addr.IP == nil {
		// Wildcard address - use IPv6 dual-stack (accepts both IPv4 and IPv6)
		family = unix.AF_INET6
		sa := &unix.SockaddrInet6{Port: addr.Port}
		// sa.Addr is zero (::), which means all interfaces
		sockaddr = sa
		ipv6only = 0 // Enable dual-stack (accept IPv4-mapped IPv6 addresses)
	} else if addr.IP.To4() != nil {
		// Explicit IPv4 address
		family = unix.AF_INET
		sa := &unix.SockaddrInet4{Port: addr.Port}
		copy(sa.Addr[:], addr.IP.To4())
		sockaddr = sa
	} else {
		// Explicit IPv6 address
		family = unix.AF_INET6
		sa := &unix.SockaddrInet6{Port: addr.Port}
		copy(sa.Addr[:], addr.IP.To16())
		// Handle zone ID for link-local addresses (fe80::)
		if addr.Zone != "" {
			if iface, err := net.InterfaceByName(addr.Zone); err == nil {
				sa.ZoneId = uint32(iface.Index)
			}
		}
		sockaddr = sa
		ipv6only = 1 // IPv6-only for explicit IPv6 addresses
	}

	// For dedicated IPv6 sockets on FreeBSD, creating the socket with non-blocking
	// and close-on-exec flags atomically is more reliable than setting them later.
	// This reverses a workaround that is only appropriate for dual-stack sockets.
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	// CRITICAL FOR FREEBSD: Set socket options in the correct order to avoid connection hangs.
	// 1. Set IPV6_V6ONLY for IPv6 sockets.
	// 2. Set non-blocking mode.
	// 3. Set SO_REUSEADDR.
	// On FreeBSD, SetNonblock must be called *before* SO_REUSEADDR on dual-stack sockets.
	if family == unix.AF_INET6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, ipv6only); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("failed to set IPV6_V6ONLY: %w", err)
		}
	}

	// Set SO_REUSEADDR to allow fast restart
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to set SO_REUSEADDR: %w", err)
	}

	// On FreeBSD, set SO_REUSEPORT to better handle separate IPv4/IPv6 listeners on the same port.
	// This is conditional to avoid potential side effects on other OSes.
	if runtime.GOOS == "freebsd" {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("failed to set SO_REUSEPORT: %w", err)
		}
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
