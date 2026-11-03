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

// drainQuietPeriod is how long a backend must stay quiet before it is reported safe to
// stop: nothing pending, and by its own report no client session (one that could add an
// upload or lose work) open and none started. The period is measured between the node's reports (the database clock),
// so it is time the node itself saw. Variables so tests can shorten them.
var drainQuietPeriod = 2 * time.Minute

// drainPollInterval is how often --wait re-reads the backend's state.
var drainPollInterval = 10 * time.Second

// sessionsReportMaxAge is how old a node's sessions report may be and still be relied
// on: a few missed reports. An older one comes from a node that stopped reporting.
var sessionsReportMaxAge = 6 * db.SessionsReportInterval

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

	// The instance id is what tells, later, whether the backend is safe to stop. One no
	// node ever used has nothing pending and no sessions, and would read as drained.
	state, err := rdb.GetInstanceDrainStateWithRetry(masterContext(ctx), instance, globalConfig.Uploader.MaxAttempts)
	if err != nil {
		return fmt.Errorf("check uploader instance %s: %w", instance, err)
	}
	if !state.Known {
		return unknownInstanceError(ctx, rdb, instance, defaulted)
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
		fmt.Printf("\nNo --instance given: its uploads and sessions are tracked under instance id %q (the host).\n", instance)
	}
	if state.Sessions == nil {
		fmt.Printf("\nInstance %s does not report its sessions (a build that predates the report): --wait\n", instance)
		fmt.Printf("cannot confirm it is safe to stop until it runs one that does.\n")
	}
	if w := staleReportWarning(state); w != "" {
		fmt.Printf("\n%s\n", w)
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
	return waitUntilSafeToStop(ctx, rdb, row.Host)
}

// staleReportWarning says when an instance's latest sessions report is old: the id is
// known (a node once ran under it) but no node runs under it now, or that node is down.
func staleReportWarning(s db.InstanceDrainState) string {
	if s.Sessions == nil || s.ReportAge <= sessionsReportMaxAge {
		return ""
	}
	return fmt.Sprintf("WARNING: instance %s last reported %s ago: no node runs under this id now, or it is down.\n"+
		"If the backend runs under another id, correct it with --instance.", s.Sessions.InstanceID, formatDuration(s.ReportAge))
}

// unknownInstanceError refuses an instance id nothing was ever recorded under, naming the
// ones an operator can choose from.
func unknownInstanceError(ctx context.Context, rdb *resilient.ResilientDatabase, instance string, defaulted bool) error {
	msg := fmt.Sprintf("no uploader instance %q has ever reported (no heartbeat, sessions report or pending upload)", instance)
	if defaulted {
		msg += "; --instance defaults to --host, and the backend's uploader runs under another id"
	}
	msg += ": pass the backend's [uploader] instance_id (default: its hostname) with --instance"
	if known, err := rdb.ListUploaderInstancesWithRetry(masterContext(ctx), time.Now().Add(-24*time.Hour)); err == nil && len(known) > 0 {
		ids := make([]string, len(known))
		for i, k := range known {
			ids[i] = k.InstanceID
		}
		msg += ". Instances seen in the last 24h: " + strings.Join(ids, ", ")
	}
	return errors.New(msg)
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
		if err := waitUntilSafeToStop(ctx, rdb, only); err != nil {
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
		state, err := rdb.GetInstanceDrainStateWithRetry(ctx, r.InstanceID, globalConfig.Uploader.MaxAttempts)
		if err != nil {
			return fmt.Errorf("drain state of %s: %w", r.InstanceID, err)
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
		printDrainState(state)
		fmt.Println()
	}

	if shown == 0 {
		if only != "" {
			return errNotInMaintenance
		}
		fmt.Printf("No backends in maintenance.\n")
		return nil
	}
	fmt.Printf("Safe to stop needs, for %s, nothing pending and no client session open or started,\n", drainQuietPeriod)
	fmt.Printf("by the node's own report: use --host <host> --wait.\n")
	fmt.Printf("Also check the node's own relay queue (sora-admin relay stats, on that node).\n")
	fmt.Printf("Each proxy reports the hosts it honors in sora_backend_maintenance_hosts, and marks its\n")
	fmt.Printf("pool backends [maintenance] in: sora-admin health status --backends\n")
	return nil
}

func printDrainState(s db.InstanceDrainState) {
	if !s.Known {
		fmt.Printf("  UNKNOWN INSTANCE:     no uploader ever reported under this id, so nothing below means\n")
		fmt.Printf("                        anything. Correct it: backends maintenance on --host <host> --instance <id>\n")
	}
	fmt.Printf("  Pending uploads:      %d", s.Pending)
	if s.Oldest != nil {
		fmt.Printf(" (oldest %s ago)", formatDuration(time.Since(*s.Oldest)))
	}
	fmt.Println()
	if s.Parked > 0 {
		fmt.Printf("  Parked uploads:       %d — out of attempts; they will not drain on their own.\n", s.Parked)
		fmt.Printf("                        Run 'sora-admin uploader resolve' on that node before stopping it.\n")
	}
	switch {
	case s.Sessions == nil:
		fmt.Printf("  Client sessions:      not reported (the node runs a build that does not report them)\n")
	default:
		fmt.Printf("  Client sessions:      %d open, %d started since %s (reported %s ago)\n",
			s.Sessions.Open, s.Sessions.Started, s.Sessions.Since.Format(time.RFC3339), formatDuration(s.ReportAge))
		if s.ReportAge > sessionsReportMaxAge {
			fmt.Printf("                        The node stopped reporting: is it running?\n")
		}
	}
}

// waitUntilSafeToStop blocks until the backend has been quiet for drainQuietPeriod: no
// upload pending and, by the node's own report, no client session open and none started. Each poll re-reads the maintenance row, so a corrected instance id is followed
// (from scratch), and the wait gives up if maintenance is turned off. It reads from the
// primary: a replica lagging behind could report zero while rows exist.
func waitUntilSafeToStop(ctx context.Context, rdb *resilient.ResilientDatabase, host string) error {
	ctx = masterContext(ctx)
	var (
		instance     string
		quiet        *quietMark // the report that began the current quiet period
		warnedParked bool
	)

	for {
		row, found, err := findMaintenance(ctx, rdb, host)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("backend %s is not in maintenance (any more): nothing to wait for", host)
		}
		now := time.Now().Format(time.TimeOnly)
		if row.InstanceID != instance {
			if instance != "" {
				fmt.Printf("%s  instance changed from %s to %s — starting over\n", now, instance, row.InstanceID)
			}
			instance = row.InstanceID
			quiet = nil
		}

		state, err := rdb.GetInstanceDrainStateWithRetry(ctx, instance, globalConfig.Uploader.MaxAttempts)
		if err != nil {
			return fmt.Errorf("drain state of %s: %w", instance, err)
		}

		if busy := notQuiet(state); busy != "" {
			if quiet != nil {
				fmt.Printf("%s  %s: no longer quiet — restarting the %s quiet period\n", now, instance, drainQuietPeriod)
			}
			quiet = nil
			fmt.Printf("%s  %s: %s\n", now, instance, busy)
			if state.Parked > 0 && !warnedParked {
				fmt.Printf("          Parked uploads are out of attempts and will not drain on their own:\n")
				fmt.Printf("          run 'sora-admin uploader resolve' on that node.\n")
				warnedParked = true
			}
		} else {
			mark := quietMark{since: state.Sessions.Since, started: state.Sessions.Started, at: state.ReportedAt}
			switch {
			case quiet == nil:
				quiet = &mark
				fmt.Printf("%s  %s: nothing pending, no client sessions — confirming for %s\n", now, instance, drainQuietPeriod)
			case !mark.since.Equal(quiet.since):
				quiet = &mark
				fmt.Printf("%s  %s: the node restarted — restarting the %s quiet period\n", now, instance, drainQuietPeriod)
			case mark.started != quiet.started:
				fmt.Printf("%s  %s: %d client sessions came and went — restarting the %s quiet period\n", now, instance, mark.started-quiet.started, drainQuietPeriod)
				quiet = &mark
			case mark.at.Sub(quiet.at) >= drainQuietPeriod:
				fmt.Printf("%s  %s: quiet for %s: nothing pending, no client session open or started.\n\n", now, instance, drainQuietPeriod)
				fmt.Printf("Backend %s is safe to stop as far as uploads go. Before stopping it, check its relay\n", host)
				fmt.Printf("queue on the node (sora-admin relay stats).\n")
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(drainPollInterval):
		}
	}
}

// quietMark is the sessions report a quiet period is measured from.
type quietMark struct {
	since   time.Time // the reporting process's start: a restart begins a new count
	started int64     // sessions started by then
	at      time.Time // when the node wrote the report (database clock)
}

// notQuiet says what keeps an instance from being quiet, or "" when it is: nothing
// pending, and a current report of no open client session. Without a usable report the
// sessions are unknown, which is never quiet.
func notQuiet(s db.InstanceDrainState) string {
	var busy []string
	if !s.Known {
		busy = append(busy, "unknown instance: no uploader ever reported under this id. Correct it with: backends maintenance on --host <host> --instance <id>")
	}
	if s.Pending > 0 {
		pending := fmt.Sprintf("%d uploads pending", s.Pending)
		if s.Parked > 0 {
			pending += fmt.Sprintf(" (%d parked)", s.Parked)
		}
		busy = append(busy, pending)
	}
	switch {
	case !s.Known:
	case s.Sessions == nil:
		busy = append(busy, "the node does not report its sessions (a build that predates the report): cannot confirm")
	case s.ReportAge > sessionsReportMaxAge:
		busy = append(busy, fmt.Sprintf("no sessions report for %s: is the node running?", formatDuration(s.ReportAge)))
	case s.Sessions.Open > 0:
		busy = append(busy, fmt.Sprintf("%d sessions open", s.Sessions.Open))
	}
	return strings.Join(busy, "; ")
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
  --instance string   The backend's uploader instance id ([uploader] instance_id, default
                      its hostname): its uploads must drain, and the node reports its
                      sessions under it. Default: the host. An id no node ever reported
                      under is refused.
  --reason string     Note shown by status.
  --wait              Block until the backend has been quiet for %s: nothing pending, and
                      by the node's own report no client session (IMAP or POP3 logged in,
                      LMTP, Admin API delivery) open or started.

Proxies need database access to honor maintenance; they re-read the list every
[backend_maintenance] poll_interval (default 5s).

Examples:
  sora-admin backends maintenance on --host storage2.example.com --reason "disk swap" --wait
  sora-admin backends status
  sora-admin backends maintenance off --host storage2.example.com
`, drainQuietPeriod)
}
