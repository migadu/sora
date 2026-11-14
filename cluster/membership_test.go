package cluster

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

const membershipTestKey = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="

// recordedLogs collects what the logger package logs while a test runs.
type recordedLogs struct {
	mu      sync.Mutex
	records []slog.Record
}

func (r *recordedLogs) Enabled(context.Context, slog.Level) bool { return true }
func (r *recordedLogs) WithAttrs([]slog.Attr) slog.Handler       { return r }
func (r *recordedLogs) WithGroup(string) slog.Handler            { return r }
func (r *recordedLogs) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec.Clone())
	return nil
}

func (r *recordedLogs) find(match func(slog.Record) bool) (slog.Record, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rec := range r.records {
		if match(rec) {
			return rec, true
		}
	}
	return slog.Record{}, false
}

func recordLogs(t *testing.T) *recordedLogs {
	rec := &recordedLogs{}
	prev := logger.Swap(slog.New(rec))
	t.Cleanup(func() { logger.Swap(prev) })
	return rec
}

// recordText is the record's message followed by its attributes.
func recordText(rec slog.Record) string {
	var b strings.Builder
	b.WriteString(rec.Message)
	rec.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%s", a.Key, a.Value)
		return true
	})
	return b.String()
}

func attr(rec slog.Record, key string) (slog.Value, bool) {
	var v slog.Value
	found := false
	rec.Attrs(func(a slog.Attr) bool {
		if a.Key == key {
			v, found = a.Value, true
			return false
		}
		return true
	})
	return v, found
}

// freeLoopbackPort returns a port that is free for both TCP and UDP on host.
func freeLoopbackPort(t *testing.T, host string) int {
	t.Helper()
	for range 20 {
		l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			t.Skipf("no %s loopback: %v", host, err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		u, err := net.ListenPacket("udp", net.JoinHostPort(host, fmt.Sprint(port)))
		l.Close()
		if err == nil {
			u.Close()
			return port
		}
	}
	t.Fatalf("no free TCP+UDP port on %s", host)
	return 0
}

func startMembershipTestNode(t *testing.T, nodeID, addr string, peers []string) *Manager {
	t.Helper()
	m, err := New(config.ClusterConfig{
		Enabled:   true,
		Addr:      addr,
		NodeID:    nodeID,
		Peers:     peers,
		SecretKey: membershipTestKey,
	})
	if err != nil {
		t.Fatalf("start %s on %s: %v", nodeID, addr, err)
	}
	t.Cleanup(func() { _ = m.Shutdown() })
	return m
}

// TestMemberlistLogsKeepTheirLevel: memberlist reports failed push/pull, packets
// it cannot decrypt (a node with another secret_key) and nodes it marks failed
// through its log output. Those lines must reach the log at their own level.
func TestMemberlistLogsKeepTheirLevel(t *testing.T) {
	logs := recordLogs(t)
	w := &memberlistLogger{prefix: "[Memberlist] "}

	lines := []struct {
		line  string
		level slog.Level
		text  string
	}{
		{"2026/11/14 10:00:00 [ERR] memberlist: Decrypt packet failed: no installed keys could decrypt the message\n", slog.LevelError, "Decrypt packet failed"},
		{"2026/11/14 10:00:00 [ERROR] memberlist: Failed to send gossip to 192.0.2.11:7946: boom\n", slog.LevelError, "Failed to send gossip"},
		{"2026/11/14 10:00:00 [WARN] memberlist: Was able to connect to node-b over TCP but UDP probes failed\n", slog.LevelWarn, "UDP probes failed"},
		{"2026/11/14 10:00:00 [INFO] memberlist: Marking node-b as failed, suspect timeout reached (0 peer confirmations)\n", slog.LevelInfo, "Marking node-b as failed"},
		{"2026/11/14 10:00:00 [DEBUG] memberlist: Initiating push/pull sync with: node-b 192.0.2.11:7946\n", slog.LevelDebug, "Initiating push/pull sync"},
	}

	for _, l := range lines {
		if _, err := w.Write([]byte(l.line)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	for _, l := range lines {
		rec, ok := logs.find(func(r slog.Record) bool { return strings.Contains(r.Message, l.text) })
		if !ok {
			t.Errorf("memberlist line %q was not logged", l.text)
			continue
		}
		if rec.Level != l.level {
			t.Errorf("memberlist line %q logged at %s, want %s", l.text, rec.Level, l.level)
		}
	}
}

// TestClusterAddrIPv6 starts a node on an IPv6 address given as addr.
func TestClusterAddrIPv6(t *testing.T) {
	port := freeLoopbackPort(t, "::1")
	m := startMembershipTestNode(t, "ipv6-node", fmt.Sprintf("[::1]:%d", port), nil)

	members := m.GetMembers()
	if len(members) != 1 || members[0].Addr != "::1" || int(members[0].Port) != port {
		t.Fatalf("members = %+v, want this node on [::1]:%d", members, port)
	}
}

// TestNewIgnoresItsOwnAddressInPeers: a peers list shared by every node names
// each node's own address. New must drop those entries, whichever form names
// the address, and say so.
func TestNewIgnoresItsOwnAddressInPeers(t *testing.T) {
	cases := []struct {
		name  string
		host  string
		peers func(port int) []string
	}{
		{"IPv4", "127.0.0.1", func(port int) []string {
			return []string{fmt.Sprintf("127.0.0.1:%d", port), "127.0.0.1", fmt.Sprintf("localhost:%d", port)}
		}},
		{"IPv6", "::1", func(port int) []string {
			return []string{fmt.Sprintf("[::1]:%d", port), "::1", fmt.Sprintf("[0:0:0:0:0:0:0:1]:%d", port)}
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := recordLogs(t)
			port := freeLoopbackPort(t, tc.host)
			nodeID := "self-peer-" + strings.ToLower(tc.name)
			own := tc.peers(port)
			startMembershipTestNode(t, nodeID, net.JoinHostPort(tc.host, fmt.Sprint(port)), own)

			started, ok := logs.find(func(r slog.Record) bool {
				node, _ := attr(r, "node_id")
				return r.Message == "Cluster manager started" && node.String() == nodeID
			})
			if !ok {
				t.Fatal("no \"Cluster manager started\" record")
			}
			peers, _ := attr(started, "peers")
			if kept, _ := peers.Any().([]string); len(kept) != 0 {
				t.Errorf("peers kept after filtering = %q, want none: every entry names this node", kept)
			}

			if _, ok := logs.find(func(r slog.Record) bool {
				text := recordText(r)
				return r.Level == slog.LevelWarn && strings.Contains(r.Message, "own") &&
					slices.ContainsFunc(own, func(p string) bool { return strings.Contains(text, p) })
			}); !ok {
				t.Error("no warning that peers lists this node's own address")
			}
		})
	}
}

// TestConfiguredPeerIsRejoinedAfterItLeft: memberlist never contacts a node again
// once it has marked it dead or left. A configured peer that comes back knowing
// nobody (here: the seed node restarting) must be joined again by the node that
// lists it, or the two stay apart until one of them restarts.
func TestConfiguredPeerIsRejoinedAfterItLeft(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the rejoin interval")
	}

	port := freeLoopbackPort(t, "127.0.0.1")
	seedAddr := fmt.Sprintf("127.0.0.1:%d", port)

	seed, err := New(config.ClusterConfig{Enabled: true, Addr: seedAddr, NodeID: "rejoin-seed", SecretKey: membershipTestKey})
	if err != nil {
		t.Fatalf("start seed: %v", err)
	}
	member := startMembershipTestNode(t, "rejoin-member", "127.0.0.1:0", []string{seedAddr})

	waitForMemberCount(t, 10*time.Second, 2, seed, member)

	// Stay complete for longer than a join retry period first: what has to heal
	// is a cluster that had formed, not one still finishing its startup join.
	time.Sleep(11 * time.Second)

	if err := seed.Shutdown(); err != nil {
		t.Fatalf("stop seed: %v", err)
	}
	waitForMemberCount(t, 10*time.Second, 1, member)

	restarted := startMembershipTestNode(t, "rejoin-seed", seedAddr, nil)
	waitForMemberCount(t, 20*time.Second, 2, restarted, member)
}

func waitForMemberCount(t *testing.T, timeout time.Duration, want int, nodes ...*Manager) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		done := true
		for _, n := range nodes {
			done = done && n.GetMemberCount() == want
		}
		if done {
			return
		}
		if time.Now().After(deadline) {
			counts := make([]string, len(nodes))
			for i, n := range nodes {
				counts[i] = fmt.Sprintf("%s=%d", n.GetNodeID(), n.GetMemberCount())
			}
			t.Fatalf("after %s members are %s, want %d each", timeout, strings.Join(counts, " "), want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
