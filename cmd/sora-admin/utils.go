package main

import (
	"fmt"
	"time"
)

// formatBytes formats a byte count as a human-readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// formatDuration formats a duration as a human-readable string
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	return fmt.Sprintf("%.1fd", d.Hours()/24)
}

// getStatusColor returns an ANSI color code for a status
func getStatusColor(status interface{}) string {
	var statusStr string
	switch v := status.(type) {
	case string:
		statusStr = v
	default:
		statusStr = fmt.Sprintf("%v", v)
	}

	switch statusStr {
	case "healthy":
		return "\033[32m" // green
	case "unhealthy":
		return "\033[31m" // red
	case "degraded":
		return "\033[33m" // yellow
	default:
		return "\033[0m" // reset
	}
}

// showComponentHistory shows historical status for a component
// Returns nil to match expected signature
func showComponentHistory(ctx interface{}, rdb interface{}, hostname, component string, since time.Time) error {
	// This function needs to be implemented based on requirements
	fmt.Printf("Component history for %s/%s since %s\n", hostname, component, since)
	fmt.Println("(History feature not yet implemented)")
	return nil
}
