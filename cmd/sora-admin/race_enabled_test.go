//go:build race

package main

// raceEnabled reports a -race build: the race detector makes sync.Pool drop a share of what
// is put back, so a test that counts on reuse cannot measure it.
const raceEnabled = true
