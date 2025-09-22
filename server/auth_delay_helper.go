package server

import (
	"context"
	"log"
	"net"
	"time"
)

// AuthDelayHelper provides delay functionality for authentication rate limiting
type AuthDelayHelper interface {
	GetAuthenticationDelay(remoteAddr net.Addr) time.Duration
}

// ApplyAuthenticationDelay applies progressive delays before authentication attempts
func ApplyAuthenticationDelay(ctx context.Context, limiter interface{}, remoteAddr net.Addr, protocol string) {
	delayHelper, ok := limiter.(AuthDelayHelper)
	if !ok || delayHelper == nil {
		return
	}

	delay := delayHelper.GetAuthenticationDelay(remoteAddr)
	if delay > 0 {
		ip, _, err := net.SplitHostPort(remoteAddr.String())
		if err != nil {
			ip = remoteAddr.String()
		}

		log.Printf("[%s-AUTH-DELAY] Applying %v delay for IP %s", protocol, delay, ip)

		// Use context-aware delay to allow cancellation
		timer := time.NewTimer(delay)
		defer timer.Stop()

		select {
		case <-timer.C:
			// Delay completed normally
			log.Printf("[%s-AUTH-DELAY] Delay completed for IP %s", protocol, ip)
		case <-ctx.Done():
			// Context cancelled (connection closed, server shutdown, etc.)
			log.Printf("[%s-AUTH-DELAY] Delay cancelled for IP %s: %v", protocol, ip, ctx.Err())
			return
		}
	}
}

// GetIPString safely extracts IP address from net.Addr
func GetIPString(addr net.Addr) string {
	if ip, _, err := net.SplitHostPort(addr.String()); err == nil {
		return ip
	}
	return addr.String()
}
