// Package checkpoint implements signed tree heads ("checkpoints"), Ed25519
// key handling with strict file permissions, and crash-safe atomic file writes.
package checkpoint

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Aolost/tamperlog/merkle"
)

// Version is the checkpoint format version.
const Version byte = 1

// Magic identifies a checkpoint.
var Magic = [4]byte{'T', 'L', 'C', 'K'}

const (
	bodySize = 4 + 1 + 32 + 8 + merkle.HashSize + 8
	// Size is the encoded size of a checkpoint.
	Size = bodySize + ed25519.SignatureSize
)

// signingPrefix provides domain separation for checkpoint signatures.
const signingPrefix = "tamperlog checkpoint v1\n"

// Checkpoint is a signed statement that the log with LogID had TreeSize
// entries with the given Merkle Root at Timestamp.
type Checkpoint struct {
	LogID     [32]byte
	TreeSize  uint64
	Root      merkle.Hash
	Timestamp int64 // Unix nanoseconds
	Signature [ed25519.SignatureSize]byte
}

// Errors.
var (
	ErrDecode    = errors.New("checkpoint: malformed")
	ErrSignature = errors.New("checkpoint: signature verification failed")
)

func (c *Checkpoint) body() []byte {
	b := make([]byte, 0, bodySize)
	b = append(b, Magic[:]...)
	b = append(b, Version)
	b = append(b, c.LogID[:]...)
	b = binary.BigEndian.AppendUint64(b, c.TreeSize)
	b = append(b, c.Root[:]...)
	return binary.BigEndian.AppendUint64(b, uint64(c.Timestamp))
}

func (c *Checkpoint) message() []byte {
	return append([]byte(signingPrefix), c.body()...)
}

// Sign creates a checkpoint signed with priv.
func Sign(priv ed25519.PrivateKey, logID [32]byte, size uint64, root merkle.Hash, ts time.Time) *Checkpoint {
	c := &Checkpoint{LogID: logID, TreeSize: size, Root: root, Timestamp: ts.UnixNano()}
	copy(c.Signature[:], ed25519.Sign(priv, c.message()))
	return c
}

// Verify checks the signature against pub.
func (c *Checkpoint) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, c.message(), c.Signature[:]) {
		return ErrSignature
	}
	return nil
}

// Time returns the signing time.
func (c *Checkpoint) Time() time.Time { return time.Unix(0, c.Timestamp).UTC() }

// MarshalBinary encodes the checkpoint (Size bytes).
func (c *Checkpoint) MarshalBinary() ([]byte, error) {
	return append(c.body(), c.Signature[:]...), nil
}

// Unmarshal decodes exactly one checkpoint.
func Unmarshal(b []byte) (*Checkpoint, error) {
	if len(b) != Size {
		return nil, fmt.Errorf("%w: length %d", ErrDecode, len(b))
	}
	if !bytes.Equal(b[0:4], Magic[:]) {
		return nil, fmt.Errorf("%w: bad magic", ErrDecode)
	}
	if b[4] != Version {
		return nil, fmt.Errorf("%w: version %d", ErrDecode, b[4])
	}
	c := &Checkpoint{}
	copy(c.LogID[:], b[5:37])
	c.TreeSize = binary.BigEndian.Uint64(b[37:45])
	copy(c.Root[:], b[45:77])
	c.Timestamp = int64(binary.BigEndian.Uint64(b[77:85]))
	copy(c.Signature[:], b[85:])
	return c, nil
}

// ReadFile reads and decodes a checkpoint file (no signature check).
func ReadFile(path string) (*Checkpoint, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Unmarshal(b)
}

// WriteFileAtomic writes data to path crash-safely: write path.tmp, fsync it,
// rename it over path, fsync the directory.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// SyncDir makes renames and creations in dir durable. The implementation is
// platform specific: see syncdir_unix.go and syncdir_windows.go.
func SyncDir(dir string) error { return syncDir(dir) }
