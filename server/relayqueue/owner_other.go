//go:build !unix

package relayqueue

// foreignOwner returns nil: there is no file owner to keep on this platform.
func foreignOwner(string) (*fileOwner, error) {
	return nil, nil
}
