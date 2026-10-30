package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
)

// drainQuietPeriod is how long a backend's upload backlog must stay at zero before it is
// reported safe to stop. A single zero proves little: an IMAP session the proxies have not
// closed yet can still APPEND, and the drain closes sessions gradually. A variable so tests
// can shorten it.
var drainQuietPeriod = 2 * time.Minute

// drainPollInterval is how often --wait re-reads the backlog.
var drainPollInterval = 10 * time.Second

// errNotInMaintenance reports a --host that is not in maintenance.
var errNotInMaintenance = errors.New("not in maintenance")

func handleBackendsCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printBackendsUsage()
		os.Exit(1)
	}

	switch os.Args[2] {
	case "maintenance":
		handleBackendsMaintenance(ctx)
	case "status":
		handleBackendsStatus(ctx)
	case "help", "--help", "-h":
		printBackendsUsage()
	default:
		fmt.Printf("Unknown backends subcommand: %s\n\n", os.Args[2])
		printBackendsUsage()
		os.Exit(1)
	}
}

func handleBackendsMaintenance(ctx context.Context) {
	if len(os.Args) < 4 || (os.Args[3] != "on" && os.Args[3] != "off") {
		printBackendsUsage()
		os.Exit(1)
	}
	action := os.Args[3]

	fs := flag.NewFlagSet("backends maintenance "+action, flag.ExitOnError)
	host := fs.String("host", "", "Backend host (name or IP, no port) as the proxies know it (REQUIRED)")
	var instance, reason *string
	var wait *bool
	if action == "on" {
		instance = fs.String("instance", "", "Uploader instance id of the backend (default: the host)")
		reason = fs.String("reason", "", "Why the backend is in maintenance (shown by status)")
		wait = fs.Bool("wait", false, "Wait until the backend is safe to stop")
	}
	fs.Usage = printBackendsUsage
	if err := fs.Parse(os.Args[4:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	h, err := normalizeBackendHost(*host)
	if err != nil {
		fmt.Printf("Error: %v\n\n", err)
		printBackendsUsage()
		os.Exit(1)
	}

	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}
	defer rdb.Close()

	if action == "off" {
		if err := maintenanceOff(ctx, rdb, h); err != nil {
			logger.Fatalf("Failed to end maintenance: %v", err)
		}
		return
	}
	if err := maintenanceOn(ctx, rdb, h, *instance, *reason, *wait); err != nil {
		logger.Fatalf("Failed to start maintenance: %v", err)
	}
}

func maintenanceOn(ctx context.Context, rdb *resilient.ResilientDatabase, host, instance, reason string, wait bool) error {
	defaulted := false
	if instance = strings.TrimSpace(instance); instance == "" {
		instance = host
		defaulted = true
	}

	row, err := rdb.SetBackendMaintenanceWithRetry(ctx, db.BackendMaintenance{
		Host:       host,
		InstanceID: instance,
		Reason:     reason,
		CreatedBy:  operatorName(),
	})
	if err != nil {
		return err
	}

	fmt.Printf("Backend %s is in maintenance (since %s).\n", row.Host, row.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Proxies stop routing new traffic to it within one poll ([backend_maintenance] poll_interval,\n")
	fmt.Printf("default 5s) and close its IMAP sessions gradually. The backend itself must keep running.\n")
	if defaulted {
		fmt.Printf("\nNo --instance given: its uploads are tracked under instance id %q (the host).\n", instance)
		fmt.Printf("If the backend's uploader runs under another id, rerun with --instance.\n")
	}

	rows, err := rdb.ListBackendMaintenanceWithRetry(masterContext(ctx))
	if err == nil {
		hosts := make([]string, len(rows))
		for i, r := range rows {
			hosts[i] = r.Host
		}
		fmt.Printf("\nAll backends in maintenance: %s\n", strings.Join(hosts, ", "))
	}

	if !wait {
		fmt.Printf("\nWhen to stop it: sora-admin backends status --host %s --wait\n", row.Host)
		return nil
	}
	fmt.Println()
	return waitUntilSafeToStop(ctx, rdb, row.Host, row.InstanceID)
}

func maintenanceOff(ctx context.Context, rdb *resilient.ResilientDatabase, host string) error {
	existed, err := rdb.ClearBackendMaintenanceWithRetry(ctx, host)
	if err != nil {
		return err
	}
	if !existed {
		fmt.Printf("Backend %s was not in maintenance.\n", host)
		return nil
	}
	fmt.Printf("Backend %s is out of maintenance. Proxies route to it again within one poll.\n", host)
	fmt.Printf("Users moved off it keep their new backend until their affinity expires.\n")
	return nil
}

func handleBackendsStatus(ctx context.Context) {
	fs := flag.NewFlagSet("backends status", flag.ExitOnError)
	host := fs.String("host", "", "Show only this backend")
	wait := fs.Bool("wait", false, "Wait until the backend (--host) is safe to stop")
	fs.Usage = printBackendsUsage
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	only := ""
	if *host != "" || *wait {
		h, err := normalizeBackendHost(*host)
		if err != nil {
			fmt.Printf("Error: %v\n\n", err)
			printBackendsUsage()
			os.Exit(1)
		}
		only = h
	}

	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}
	defer rdb.Close()

	if *wait {
		if err := waitUntilSafeToStop(ctx, rdb, only, ""); err != nil {
			logger.Fatalf("%v", err)
		}
		return
	}
	if err := showBackendsStatus(ctx, rdb, only); errors.Is(err, errNotInMaintenance) {
		fmt.Printf("Backend %s is not in maintenance.\n", only)
		os.Exit(1)
	} else if err != nil {
		logger.Fatalf("Failed to show backend status: %v", err)
	}
}

func showBackendsStatus(ctx context.Context, rdb *resilient.ResilientDatabase, only string) error {
	ctx = masterContext(ctx)
	rows, err := rdb.ListBackendMaintenanceWithRetry(ctx)
	if err != nil {
		return err
	}

	shown := 0
	for _, r := range rows {
		if only != "" && r.Host != only {
			continue
		}
		shown++
		backlog, err := rdb.GetInstanceUploadBacklogWithRetry(ctx, r.InstanceID, globalConfig.Uploader.MaxAttempts)
		if err != nil {
			return fmt.Errorf("upload backlog of %s: %w", r.InstanceID, err)
		}

		fmt.Printf("%s\n", r.Host)
		fmt.Printf("  In maintenance since: %s (%s ago)\n", r.CreatedAt.Format(time.RFC3339), formatDuration(time.Since(r.CreatedAt)))
		if r.CreatedBy != "" {
			fmt.Printf("  By:                   %s\n", r.CreatedBy)
		}
		if r.Reason != "" {
			fmt.Printf("  Reason:               %s\n", r.Reason)
		}
		fmt.Printf("  Uploader instance:    %s\n", r.InstanceID)
		printBacklog(backlog)
		fmt.Println()
	}

	if shown == 0 {
		if only != "" {
			return errNotInMaintenance
		}
		fmt.Printf("No backends in maintenance.\n")
		return nil
	}
	fmt.Printf("Safe to stop needs the backlog at zero for %s: use --host <host> --wait.\n", drainQuietPeriod)
	fmt.Printf("Also check the node's own relay queue (sora-admin relay stats, on that node), and that\n")
	fmt.Printf("nothing reaches it except through proxies (direct LMTP, its own Admin API).\n")
	fmt.Printf("Each proxy marks the backends it honors as [maintenance] in: sora-admin health status --backends\n")
	return nil
}

func printBacklog(b db.InstanceUploadBacklog) {
	fmt.Printf("  Pending uploads:      %d", b.Pending)
	if b.Oldest != nil {
		fmt.Printf(" (oldest %s ago)", formatDuration(time.Since(*b.Oldest)))
	}
	fmt.Println()
	if b.Parked > 0 {
		fmt.Printf("  Parked uploads:       %d — out of attempts; they will not drain on their own.\n", b.Parked)
		fmt.Printf("                        Run 'sora-admin uploader resolve' on that node before stopping it.\n")
	}
}

// waitUntilSafeToStop blocks until the backend's upload backlog has stayed at zero for
// drainQuietPeriod. It reads from the primary (a replica lagging behind could report zero
// while rows exist) and gives up if maintenance is turned off meanwhile.
func waitUntilSafeToStop(ctx context.Context, rdb *resilient.ResilientDatabase, host, instance string) error {
	ctx = masterContext(ctx)
	var zeroSince time.Time
	warnedParked := false

	for {
		row, found, err := findMaintenance(ctx, rdb, host)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("backend %s is not in maintenance (any more): nothing to wait for", host)
		}
		if instance == "" {
			instance = row.InstanceID
		}

		backlog, err := rdb.GetInstanceUploadBacklogWithRetry(ctx, instance, globalConfig.Uploader.MaxAttempts)
		if err != nil {
			return fmt.Errorf("upload backlog of %s: %w", instance, err)
		}

		now := time.Now()
		switch {
		case backlog.Pending > 0:
			if !zeroSince.IsZero() {
				fmt.Printf("%s  uploads pending again — restarting the %s quiet period\n", now.Format(time.TimeOnly), drainQuietPeriod)
			}
			zeroSince = time.Time{}
			fmt.Printf("%s  %s: %d uploads pending", now.Format(time.TimeOnly), instance, backlog.Pending)
			if backlog.Parked > 0 {
				fmt.Printf(" (%d parked)", backlog.Parked)
			}
			fmt.Println()
			if backlog.Parked > 0 && !warnedParked {
				fmt.Printf("          Parked uploads are out of attempts and will not drain on their own:\n")
				fmt.Printf("          run 'sora-admin uploader resolve' on that node.\n")
				warnedParked = true
			}
		case zeroSince.IsZero():
			zeroSince = now
			fmt.Printf("%s  %s: no uploads pending — confirming for %s\n", now.Format(time.TimeOnly), instance, drainQuietPeriod)
		case now.Sub(zeroSince) >= drainQuietPeriod:
			fmt.Printf("%s  %s: no uploads pending for %s.\n\n", now.Format(time.TimeOnly), instance, drainQuietPeriod)
			fmt.Printf("Backend %s is safe to stop as far as uploads go. Before stopping it, check its relay\n", host)
			fmt.Printf("queue on the node (sora-admin relay stats) and that nothing reaches it except through proxies.\n")
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(drainPollInterval):
		}
	}
}

func findMaintenance(ctx context.Context, rdb *resilient.ResilientDatabase, host string) (db.BackendMaintenance, bool, error) {
	rows, err := rdb.ListBackendMaintenanceWithRetry(ctx)
	if err != nil {
		return db.BackendMaintenance{}, false, err
	}
	for _, r := range rows {
		if r.Host == host {
			return r, true, nil
		}
	}
	return db.BackendMaintenance{}, false, nil
}

// normalizeBackendHost validates a --host value and returns it in the form proxies match.
// A port is refused: maintenance applies to the host across every protocol it serves.
func normalizeBackendHost(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("--host is required")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return "", fmt.Errorf("--host takes a host without a port: use %q (maintenance covers every port of the host)", h)
	}
	if strings.ContainsAny(host, "/ \t") {
		return "", fmt.Errorf("invalid --host %q", host)
	}
	return proxy.NormalizeMaintenanceHost(host), nil
}

// masterContext pins reads to the primary: a lagging replica must not under-report a
// backlog or miss a maintenance row an operator just wrote.
func masterContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, consts.UseMasterDBKey, true)
}

// operatorName identifies who put a backend in maintenance: user@host of this command.
func operatorName() string {
	name := os.Getenv("USER")
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return name + "@" + h
	}
	return name
}

func printBackendsUsage() {
	fmt.Printf(`Backend maintenance

A backend in maintenance gets no new traffic from any proxy: new logins and deliveries go
to other backends, users with affinity to it are re-routed, remote-lookup routes to it
fall back to normal routing, and proxies close its IMAP sessions gradually. The backend
keeps running, so it finishes the uploads only it can do (its spool is node-local), and
is then safe to stop.

Usage:
  sora-admin backends maintenance on  --host HOST [--instance ID] [--reason TEXT] [--wait]
  sora-admin backends maintenance off --host HOST
  sora-admin backends status [--host HOST] [--wait]

Options:
  --host string       Backend host as the proxies know it: a name or an IP, without a
                      port. A name also covers the addresses it resolves to.
  --instance string   The backend's uploader instance id ([uploader] instance_id or its
                      default), whose upload backlog must drain. Default: the host.
  --reason string     Note shown by status.
  --wait              Block until the backlog has stayed at zero for %s.

Proxies need database access to honor maintenance; they re-read the list every
[backend_maintenance] poll_interval (default 5s).

Examples:
  sora-admin backends maintenance on --host storage2.example.com --reason "disk swap" --wait
  sora-admin backends status
  sora-admin backends maintenance off --host storage2.example.com
`, drainQuietPeriod)
}
