//go:build !unix

package relayqueue

import "fmt"

// Fail closed on platforms without the spool's cross-process ownership primitive.
type queueLease struct{}

func (*DiskQueue) tryLease(string) (*queueLease, error) {
	return nil, fmt.Errorf("relay queue cross-process leases require Unix")
}
func (*queueLease) close() {}
