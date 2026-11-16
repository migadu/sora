package tlsmanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"golang.org/x/crypto/acme/autocert"
)

const localPrivatePrefix = ".sora-"

type localCertificateCache struct{ dir string }
type localProvenance struct {
	Version     int                   `json:"version"`
	Fingerprint string                `json:"fingerprint"`
	Generation  publicationGeneration `json:"generation"`
}

func localDataFingerprint(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
func localMetadataName(name string) string {
	return localPrivatePrefix + "provenance-" + localDataFingerprint([]byte(name))
}
func localEntryPath(dir, name string) string { return filepath.Join(dir, filepath.Clean("/"+name)) }

// WithLocalCertificateEntry coordinates all upgraded server/admin writers using
// this directory. The callback uses the held parent FD, so an ancestor replacement
// cannot redirect the write/remove or the lock's ownership handoff.
func WithLocalCertificateEntry(ctx context.Context, path string, fn func(*os.Root, string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(path)
	unlock, err := lockLocalEntry(ctx, parent, name)
	if err != nil {
		return err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(parent, name)
}
func readLocalSnapshot(parent *os.Root, name string) ([]byte, publicationGeneration, error) {
	data, err := readLocalRegular(parent, name)
	if os.IsNotExist(err) {
		return nil, publicationGeneration{}, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, publicationGeneration{}, err
	}
	raw, err := readLocalRegular(parent, localMetadataName(name))
	if os.IsNotExist(err) {
		return data, publicationGeneration{}, nil
	}
	if err != nil {
		return nil, publicationGeneration{}, err
	}
	var p localProvenance
	if json.Unmarshal(raw, &p) != nil || p.Version != 1 || p.Fingerprint != localDataFingerprint(data) {
		return data, publicationGeneration{}, nil
	}
	return data, p.Generation, nil
}
func (c *localCertificateCache) snapshot(ctx context.Context, name string) (data []byte, g publicationGeneration, err error) {
	err = WithLocalCertificateEntry(ctx, localEntryPath(c.dir, name), func(parent *os.Root, name string) error {
		var e error
		data, g, e = readLocalSnapshot(parent, name)
		return e
	})
	return
}
func (c *localCertificateCache) Get(ctx context.Context, name string) ([]byte, error) {
	data, _, err := c.snapshot(ctx, name)
	return data, err
}

// writeLocalAtomic is synchronous. Cancellation never releases the entry lease
// while an unjoined DirCache goroutine can still rename a file behind it.
func writeLocalAtomic(ctx context.Context, parent *os.Root, name string, data []byte) error {
	temp := localPrivatePrefix + "temp-" + uuid.NewString()
	f, err := parent.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer parent.Remove(temp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := giveLocalFile(parent, f); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := parent.Rename(temp, name); err != nil {
		return err
	}
	return syncLocalDirectory(parent)
}
func writeLocalSnapshot(ctx context.Context, parent *os.Root, name string, data []byte, g publicationGeneration) error {
	if current, currentGeneration, err := readLocalSnapshot(parent, name); err == nil && (!g.Known || currentGeneration == g) && isCertificateCacheKey(name) && olderCertificate(data, current) {
		return nil
	}
	if err := writeLocalAtomic(ctx, parent, name, data); err != nil {
		return err
	}
	p := localProvenance{Version: 1, Fingerprint: localDataFingerprint(data), Generation: g}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	// If the process dies between these renames, a missing/mismatched metadata
	// record becomes unknown provenance, never permission to cross a deletion.
	return writeLocalAtomic(ctx, parent, localMetadataName(name), raw)
}
func (c *localCertificateCache) putSnapshot(ctx context.Context, name string, data []byte, g publicationGeneration) error {
	return WithLocalCertificateEntry(ctx, localEntryPath(c.dir, name), func(parent *os.Root, name string) error { return writeLocalSnapshot(ctx, parent, name, data, g) })
}
func (c *localCertificateCache) Put(ctx context.Context, name string, data []byte) error {
	return c.putSnapshot(ctx, name, data, publicationGeneration{})
}
func (c *localCertificateCache) Delete(ctx context.Context, name string) error {
	return WithLocalCertificateEntry(ctx, localEntryPath(c.dir, name), func(parent *os.Root, name string) error {
		for _, n := range []string{name, localMetadataName(name)} {
			if err := parent.Remove(n); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		return syncLocalDirectory(parent)
	})
}
func (c *localCertificateCache) deleteIfSame(ctx context.Context, name string, expected []byte, expectedGeneration ...publicationGeneration) (removed bool, err error) {
	err = WithLocalCertificateEntry(ctx, localEntryPath(c.dir, name), func(parent *os.Root, name string) error {
		current, currentGeneration, err := readLocalSnapshot(parent, name)
		if errors.Is(err, autocert.ErrCacheMiss) {
			return nil
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(current, expected) || (len(expectedGeneration) > 0 && currentGeneration != expectedGeneration[0]) {
			return nil
		}
		for _, n := range []string{name, localMetadataName(name)} {
			if err := parent.Remove(n); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		removed = true
		return syncLocalDirectory(parent)
	})
	return
}
func (c *localCertificateCache) replaceIfSame(ctx context.Context, name string, expected []byte, existed bool, data []byte, g publicationGeneration, expectedGeneration ...publicationGeneration) (replaced bool, err error) {
	err = WithLocalCertificateEntry(ctx, localEntryPath(c.dir, name), func(parent *os.Root, name string) error {
		current, currentGeneration, err := readLocalSnapshot(parent, name)
		if err != nil && !errors.Is(err, autocert.ErrCacheMiss) {
			return err
		}
		if existed {
			if err != nil || !bytes.Equal(current, expected) || (len(expectedGeneration) > 0 && currentGeneration != expectedGeneration[0]) {
				return nil
			}
		} else if err == nil {
			return nil
		}
		if bytes.Equal(current, data) {
			if _, storedGeneration, err := readLocalSnapshot(parent, name); err == nil && storedGeneration == g {
				replaced = true
				return nil
			}
		}
		if err := writeLocalSnapshot(ctx, parent, name, data, g); err != nil {
			return err
		}
		replaced = true
		return nil
	})
	return
}
func syncLocalDirectory(parent *os.Root) error {
	f, err := parent.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (fc *FallbackCache) localSnapshot(ctx context.Context, name string) ([]byte, publicationGeneration, error) {
	if c, ok := fc.fallback.(*localCertificateCache); ok {
		return c.snapshot(ctx, name)
	}
	data, err := fc.fallback.Get(ctx, name)
	return data, publicationGeneration{}, err
}
func (fc *FallbackCache) storeLocal(ctx context.Context, name string, data []byte, g publicationGeneration) error {
	if c, ok := fc.fallback.(*localCertificateCache); ok {
		return c.putSnapshot(ctx, name, data, g)
	}
	return fc.fallback.Put(ctx, name, data)
}
func (fc *FallbackCache) removeLocalIfSame(ctx context.Context, name string, data []byte, expectedGeneration ...publicationGeneration) error {
	if c, ok := fc.fallback.(*localCertificateCache); ok {
		_, err := c.deleteIfSame(ctx, name, data, expectedGeneration...)
		return err
	}
	current, err := fc.fallback.Get(ctx, name)
	if errors.Is(err, autocert.ErrCacheMiss) {
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(current, data) {
		return nil
	}
	return fc.fallback.Delete(ctx, name)
}
func (fc *FallbackCache) replaceLocalIfSame(ctx context.Context, name string, old []byte, existed bool, data []byte, g publicationGeneration, expectedGeneration ...publicationGeneration) error {
	if c, ok := fc.fallback.(*localCertificateCache); ok {
		_, err := c.replaceIfSame(ctx, name, old, existed, data, g, expectedGeneration...)
		return err
	}
	current, err := fc.fallback.Get(ctx, name)
	if existed {
		if err != nil || !bytes.Equal(current, old) {
			return err
		}
	} else if err == nil {
		return nil
	} else if !errors.Is(err, autocert.ErrCacheMiss) {
		return err
	}
	return fc.fallback.Put(ctx, name, data)
}
func (fc *FallbackCache) primarySnapshot(ctx context.Context, name string) ([]byte, publicationGeneration, error) {
	if c, ok := fc.primary.(interface {
		getSnapshot(context.Context, string) ([]byte, publicationGeneration, error)
	}); ok {
		return c.getSnapshot(ctx, name)
	}
	data, err := fc.primary.Get(ctx, name)
	return data, publicationGeneration{}, err
}
func (fc *FallbackCache) publicationSnapshot(ctx context.Context, name string) (publicationGeneration, error) {
	_, g, err := fc.primarySnapshot(ctx, name)
	if err == nil || errors.Is(err, autocert.ErrCacheMiss) {
		return g, nil
	}
	_, local, localErr := fc.localSnapshot(ctx, name)
	if localErr == nil && local.Known {
		return local, nil
	}
	return publicationGeneration{}, err
}

// Keep private coordination files out of bulk sync/prewarm directory inventories.
func isLocalPrivateFile(name string) bool {
	return len(name) >= len(localPrivatePrefix) && name[:len(localPrivatePrefix)] == localPrivatePrefix
}

var _ autocert.Cache = (*localCertificateCache)(nil)

func ioReadAllLocal(f *os.File) ([]byte, error) { return io.ReadAll(f) }

// DecodeCertificateCacheData lets admin readers ignore a key-free tombstone while
// preserving ordinary certificate/private-key byte formats for active entries.
func DecodeCertificateCacheData(raw []byte) (data []byte, absent bool, err error) {
	data, state, err := decodeCertificateState(raw)
	if err == nil && state.Unproven {
		err = errUnprovenSharedCertificate
	}
	return data, state.Deleted || state.Absent, err
}

// WriteLocalCertificateFile writes the certificate plus source-generation metadata
// under one held parent/entry lease. prepare preserves the admin caller's existing
// ownership/mode policy and runs before either file becomes visible.
func WriteLocalCertificateFile(ctx context.Context, path string, objectData []byte, prepare func(*os.File, os.FileInfo) error) error {
	data, state, err := decodeCertificateState(objectData)
	if err != nil {
		return err
	}
	if state.Unproven {
		return errUnprovenSharedCertificate
	}
	if state.Deleted || state.Absent {
		return autocert.ErrCacheMiss
	}
	generation := publicationGeneration{}
	if bytes.Contains(objectData, stateSeparator) {
		generation = publicationGeneration{Value: state.Generation, Known: true}
	}
	return WithLocalCertificateEntry(ctx, path, func(parent *os.Root, name string) error {
		old, err := parent.Stat(name)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		temp := localPrivatePrefix + "temp-" + uuid.NewString()
		f, err := parent.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer parent.Remove(temp)
		if prepare != nil {
			err = prepare(f, old)
		} else {
			err = giveLocalFile(parent, f)
		}
		if err == nil {
			_, err = f.Write(data)
		}
		if err == nil {
			err = f.Sync()
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := parent.Rename(temp, name); err != nil {
			return err
		}
		if err := syncLocalDirectory(parent); err != nil {
			return err
		}
		raw, err := json.Marshal(localProvenance{Version: 1, Fingerprint: localDataFingerprint(data), Generation: generation})
		if err != nil {
			return err
		}
		return writeLocalAtomic(ctx, parent, localMetadataName(name), raw)
	})
}
func ReadLocalCertificateFile(ctx context.Context, path string) (data []byte, err error) {
	err = WithLocalCertificateEntry(ctx, path, func(parent *os.Root, name string) error {
		var e error
		data, e = readLocalRegular(parent, name)
		return e
	})
	return
}
func RemoveLocalCertificateIfSame(ctx context.Context, path string, expected []byte) (bool, error) {
	c := &localCertificateCache{dir: filepath.Dir(path)}
	return c.deleteIfSame(ctx, filepath.Base(path), expected)
}

// Unknown provenance is not proof that a valid certificate was revoked. Keep that
// exact private copy for recovery while excluding it from cache reads/publication.
func (c *localCertificateCache) quarantineIfSame(ctx context.Context, name string, expected []byte, expectedGeneration ...publicationGeneration) error {
	return WithLocalCertificateEntry(ctx, localEntryPath(c.dir, name), func(parent *os.Root, name string) error {
		current, currentGeneration, err := readLocalSnapshot(parent, name)
		if errors.Is(err, autocert.ErrCacheMiss) {
			return nil
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(current, expected) || (len(expectedGeneration) > 0 && currentGeneration != expectedGeneration[0]) {
			return nil
		}
		quarantine := localPrivatePrefix + "quarantine-" + uuid.NewString()
		// Copy into a new mode-0600 inode instead of chmod/chown of a possibly
		// hard-linked preexisting file. The only authoritative name is removed last.
		if err := writeLocalAtomic(ctx, parent, quarantine, current); err != nil {
			return err
		}
		provenance, err := json.Marshal(localProvenance{Version: 1, Fingerprint: localDataFingerprint(current), Generation: publicationGeneration{}})
		if err != nil {
			return err
		}
		if err := writeLocalAtomic(ctx, parent, quarantine+".state", provenance); err != nil {
			return err
		}
		if err := parent.Remove(name); err != nil {
			return err
		}
		if err := parent.Remove(localMetadataName(name)); err != nil && !os.IsNotExist(err) {
			return err
		}

		return syncLocalDirectory(parent)
	})
}
func (fc *FallbackCache) quarantineLocalIfSame(ctx context.Context, name string, data []byte, expectedGeneration ...publicationGeneration) error {
	if c, ok := fc.fallback.(*localCertificateCache); ok {
		return c.quarantineIfSame(ctx, name, data, expectedGeneration...)
	}
	return errUnknownCertificateProvenance
}

type localRevalidationKey struct{}

func (fc *FallbackCache) validateUnknownLocal(ctx context.Context, name string, data []byte) error {
	remote, g, err := fc.primarySnapshot(ctx, name)
	if err != nil && !errors.Is(err, autocert.ErrCacheMiss) {
		fc.markS3Unavailable()
		return err
	}
	fc.markS3Available()
	localFP, _ := certificateFingerprint(data)
	remoteFP, _ := certificateFingerprint(remote)
	if g.Known && g.Value == "legacy" {
		chosen := data
		if err == nil && olderCertificate(data, remote) {
			chosen = remote
		}
		return fc.replaceLocalIfSame(ctx, name, data, true, chosen, g, publicationGeneration{})
	}
	if err == nil && localFP == remoteFP {
		return fc.replaceLocalIfSame(ctx, name, data, true, remote, g, publicationGeneration{})
	}
	if err := fc.quarantineLocalIfSame(ctx, name, data, publicationGeneration{}); err != nil {
		return err
	}
	if err == nil {
		return fc.replaceLocalIfSame(ctx, name, nil, false, remote, g)
	}
	return nil
}
