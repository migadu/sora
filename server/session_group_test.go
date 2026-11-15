package server

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A session can finish initialization after shutdown already took its active
// snapshot, but before cancellation runs its socket-close callback. The handoff
// must still close that connection rather than canceling its only closer.
func TestSessionGroupInitializationAfterDrainClosesConnection(t *testing.T) {
	var g SessionGroup
	accepted, peer := net.Pipe()
	defer accepted.Close()
	defer peer.Close()
	endInitialization := g.GuardInitialization(context.Background(), accepted)
	g.BeginDrain()
	endInitialization()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("late initialized connection remained open: %v", err)
	}
}

// Once a session is published before draining, the protocol's normal shutdown
// response must remain possible instead of racing a raw socket-close callback.
func TestSessionGroupInitializationHandsOffConnection(t *testing.T) {
	var g SessionGroup
	accepted, peer := net.Pipe()
	defer accepted.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endInitialization := g.GuardInitialization(ctx, accepted)
	endInitialization()
	cancel()
	written := make(chan error, 1)
	go func() {
		_, err := accepted.Write([]byte("bye"))
		written <- err
	}()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 3)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("initialized connection could not send shutdown response: %v", err)
	}
	if string(buf) != "bye" {
		t.Fatalf("shutdown response = %q", buf)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestSessionGroupDrainWaitsForSessions(t *testing.T) {
	var g SessionGroup
	release := make(chan struct{})
	if !g.Go(func() { <-release }) {
		t.Fatal("Go refused a session before the drain")
	}
	if g.Drain(50 * time.Millisecond) {
		t.Fatal("Drain reported every session ended while one is still running")
	}
	close(release)
	if !g.Drain(time.Second) {
		t.Fatal("Drain timed out after the only session ended")
	}
}

// Shutdown just after a connection was accepted: once the drain has begun the
// session is refused, not started behind the drain's back.
func TestSessionGroupRefusesSessionsOnceDraining(t *testing.T) {
	var g SessionGroup
	g.BeginDrain()
	ran := make(chan struct{}, 1)
	if g.Go(func() { ran <- struct{}{} }) {
		t.Error("Go started a session after the drain began")
	}
	if g.Add() {
		t.Error("Add registered a session after the drain began")
	}
	select {
	case <-ran:
		t.Error("a refused session ran")
	case <-time.After(50 * time.Millisecond):
	}
	if !g.Drain(time.Second) {
		t.Fatal("Drain of an empty group timed out")
	}
}

// Sessions registered while the drain is starting either end before Drain
// returns or are refused; none starts after it returned. Under -race this also
// checks that registration and the drain's wait are ordered (sync.WaitGroup:
// "calls with a positive delta that occur when the counter is zero must happen
// before a Wait").
func TestSessionGroupRegistrationRacingDrain(t *testing.T) {
	for range 100 {
		var g SessionGroup
		var drained, late atomic.Bool
		var acceptors, accepting sync.WaitGroup
		for range 4 {
			acceptors.Add(1)
			accepting.Add(1)
			go func() {
				defer acceptors.Done()
				for i := 0; i < 10000; i++ {
					started := g.Go(func() {
						if drained.Load() {
							late.Store(true)
						}
					})
					if i == 0 {
						accepting.Done()
					}
					if !started {
						return
					}
				}
			}()
		}
		accepting.Wait() // the drain begins while every acceptor is registering sessions
		if !g.Drain(5 * time.Second) {
			t.Fatal("Drain timed out")
		}
		drained.Store(true)
		acceptors.Wait()
		if late.Load() {
			t.Fatal("a session started after Drain returned")
		}
	}
}
