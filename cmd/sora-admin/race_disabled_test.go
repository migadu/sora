//go:build !race

package main

// raceEnabled reports a -race build; see race_enabled_test.go.
const raceEnabled = false
