// Package entry defines the canonical, versioned binary encoding of a
// tamperlog entry and the hash chain that links entries together.
package entry

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/Aolost/tamperlog/merkle"
)

// Version is the current entry format version.
const Version byte = 1

// HeaderSize is the fixed-size prefix of an encoded v1 entry.
const HeaderSize = 1 + 8 + 8 + merkle.HashSize + 4

// MaxPayload is the largest payload accepted by the encoder and decoder.
const MaxPayload = 16 << 20

// MaxEncodedSize is the largest valid encoded entry.
const MaxEncodedSize = HeaderSize + MaxPayload

// Entry is one log record.
type Entry struct {
	Seq       uint64
	Timestamp int64 // Unix nanoseconds, UTC
	PrevHash  merkle.Hash
	Payload   []byte
}

// Time returns the timestamp as a time.Time in UTC.
func (e *Entry) Time() time.Time { return time.Unix(0, e.Timestamp).UTC() }

// Decode errors.
var (
	ErrVersion  = errors.New("entry: unsupported version")
	ErrShort    = errors.New("entry: buffer too short")
	ErrLength   = errors.New("entry: payload length does not match buffer")
	ErrTooLarge = errors.New("entry: payload too large")
)

// MarshalBinary returns the canonical v1 encoding:
//
//	version u8 | seq u64 | timestamp i64 | prev_hash [32] | payload_len u32 | payload
func (e *Entry) MarshalBinary() ([]byte, error) {
	if len(e.Payload) > MaxPayload {
		return nil, ErrTooLarge
	}
	return e.AppendBinary(make([]byte, 0, HeaderSize+len(e.Payload))), nil
}

// AppendBinary appends the canonical encoding to b. The caller must ensure
// len(Payload) <= MaxPayload.
func (e *Entry) AppendBinary(b []byte) []byte {
	b = append(b, Version)
	b = binary.BigEndian.AppendUint64(b, e.Seq)
	b = binary.BigEndian.AppendUint64(b, uint64(e.Timestamp))
	b = append(b, e.PrevHash[:]...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(e.Payload)))
	return append(b, e.Payload...)
}

// Unmarshal decodes a canonical v1 entry. It rejects any buffer that is not
// exactly one entry. The returned Payload aliases b.
func Unmarshal(b []byte) (Entry, error) {
	var e Entry
	if len(b) < HeaderSize {
		return e, ErrShort
	}
	if b[0] != Version {
		return e, fmt.Errorf("%w: %d", ErrVersion, b[0])
	}
	e.Seq = binary.BigEndian.Uint64(b[1:9])
	e.Timestamp = int64(binary.BigEndian.Uint64(b[9:17]))
	copy(e.PrevHash[:], b[17:49])
	n := binary.BigEndian.Uint32(b[49:53])
	if n > MaxPayload {
		return Entry{}, ErrTooLarge
	}
	if uint64(len(b)-HeaderSize) != uint64(n) {
		return Entry{}, ErrLength
	}
	e.Payload = b[HeaderSize:]
	return e, nil
}

// Hash returns the entry hash (= Merkle leaf hash) of encoded entry bytes.
func Hash(encoded []byte) merkle.Hash { return merkle.LeafHash(encoded) }

// GenesisHash is the prev_hash of entry 0, bound to the log ID so that entries
// cannot be spliced between logs even at seq 0.
func GenesisHash(logID [32]byte) merkle.Hash {
	h := sha256.New()
	h.Write([]byte("tamperlog/v1/genesis"))
	h.Write(logID[:])
	var out merkle.Hash
	h.Sum(out[:0])
	return out
}

// ChainError describes the first link that does not verify.
type ChainError struct {
	Seq    uint64
	Reason string
}

func (e *ChainError) Error() string {
	return fmt.Sprintf("entry: chain broken at seq %d: %s", e.Seq, e.Reason)
}

// Chain verifies entries incrementally: positions, prev_hash links and
// monotonic timestamps.
type Chain struct {
	next     uint64
	prevHash merkle.Hash
	prevTS   int64
}

// NewChain starts a chain for the given log.
func NewChain(logID [32]byte) *Chain {
	return &Chain{prevHash: GenesisHash(logID), prevTS: -1 << 63}
}

// Next is the expected seq of the next entry.
func (c *Chain) Next() uint64 { return c.next }

// Head is the hash of the last accepted entry (or the genesis hash).
func (c *Chain) Head() merkle.Hash { return c.prevHash }

// LastTimestamp is the timestamp of the last accepted entry.
func (c *Chain) LastTimestamp() int64 { return c.prevTS }

// Link reasons returned in ChainError.Reason.
const (
	ReasonSeq       = "seq"
	ReasonPrevHash  = "prev_hash"
	ReasonTimestamp = "timestamp"
)

// Add checks e (whose entry hash is h) against the chain and advances it.
func (c *Chain) Add(e *Entry, h merkle.Hash) error {
	if e.Seq != c.next {
		return &ChainError{Seq: c.next, Reason: ReasonSeq}
	}
	if e.PrevHash != c.prevHash {
		return &ChainError{Seq: e.Seq, Reason: ReasonPrevHash}
	}
	if e.Timestamp < c.prevTS {
		return &ChainError{Seq: e.Seq, Reason: ReasonTimestamp}
	}
	c.next++
	c.prevHash = h
	c.prevTS = e.Timestamp
	return nil
}
