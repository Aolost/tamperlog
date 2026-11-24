// Package merkle implements the RFC 6962 / RFC 9162 Merkle tree used by
// tamperlog: leaf and node hashing, an append-only in-memory tree, inclusion
// and consistency proofs, and verifiers that need only the proof, the root(s)
// and the size(s).
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"sync"
)

// HashSize is the size of a SHA-256 digest.
const HashSize = sha256.Size

// MaxProofLen bounds the number of hashes in any proof for a tree of at most
// 2^64-1 leaves (inclusion: 64, consistency: 65 before the RFC 9162 prefix
// rule; we never emit more than 64 hashes in practice).
const MaxProofLen = 64

// Hash is a SHA-256 digest.
type Hash [HashSize]byte

// String returns the lower-case hex encoding.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// ParseHash parses a 64-character hex string.
func ParseHash(s string) (Hash, error) {
	var h Hash
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != HashSize {
		return h, fmt.Errorf("merkle: invalid hash %q", s)
	}
	copy(h[:], b)
	return h, nil
}

// EmptyRoot is MTH({}) = SHA-256 of the empty string.
var EmptyRoot = Hash(sha256.Sum256(nil))

// LeafHash returns SHA-256(0x00 || data).
func LeafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

// NodeHash returns SHA-256(0x01 || left || right).
func NodeHash(left, right Hash) Hash {
	var buf [1 + 2*HashSize]byte
	buf[0] = 0x01
	copy(buf[1:], left[:])
	copy(buf[1+HashSize:], right[:])
	return Hash(sha256.Sum256(buf[:]))
}

// Errors returned by the verifiers.
var (
	ErrInvalidProof = errors.New("merkle: invalid proof")
	ErrRootMismatch = errors.New("merkle: root mismatch")
	ErrBadRange     = errors.New("merkle: index or size out of range")
)

// largestPow2Less returns the largest power of two strictly smaller than n (n >= 2).
func largestPow2Less(n uint64) uint64 {
	return uint64(1) << (bits.Len64(n-1) - 1)
}

// Tree is an append-only Merkle tree that stores the hash of every complete,
// aligned subtree. Root and proof computation for any size up to Size() is
// O(log n). Tree is safe for concurrent use by one appender and many readers.
type Tree struct {
	mu sync.RWMutex
	// levels[l][i] = MTH of leaves [i<<l, (i+1)<<l).
	levels [][]Hash
}

// NewTree returns an empty tree.
func NewTree() *Tree { return &Tree{} }

// Size returns the number of leaves.
func (t *Tree) Size() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.size()
}

func (t *Tree) size() uint64 {
	if len(t.levels) == 0 {
		return 0
	}
	return uint64(len(t.levels[0]))
}

// AppendLeafHash appends a leaf whose hash (SHA-256(0x00||data)) is already known.
func (t *Tree) AppendLeafHash(h Hash) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.levels) == 0 {
		t.levels = append(t.levels, nil)
	}
	t.levels[0] = append(t.levels[0], h)
	idx := uint64(len(t.levels[0]) - 1)
	cur := h
	for l := 0; idx&1 == 1; l++ {
		if len(t.levels) <= l+1 {
			t.levels = append(t.levels, nil)
		}
		cur = NodeHash(t.levels[l][idx-1], cur)
		t.levels[l+1] = append(t.levels[l+1], cur)
		idx >>= 1
	}
}

// LeafHash returns the hash of leaf i.
func (t *Tree) LeafHash(i uint64) (Hash, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if i >= t.size() {
		return Hash{}, ErrBadRange
	}
	return t.levels[0][i], nil
}

// Root returns the root of the whole tree.
func (t *Tree) Root() Hash {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.mth(0, t.size())
}

// RootAt returns the root of the first n leaves.
func (t *Tree) RootAt(n uint64) (Hash, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if n > t.size() {
		return Hash{}, ErrBadRange
	}
	return t.mth(0, n), nil
}

// mth computes MTH(D[lo:hi]). lo is always aligned to the largest power of two
// that is <= hi-lo when called from the RFC recursion, so complete subtrees are
// looked up and only the right spine is hashed.
func (t *Tree) mth(lo, hi uint64) Hash {
	n := hi - lo
	switch {
	case n == 0:
		return EmptyRoot
	case n&(n-1) == 0 && lo%n == 0:
		l := bits.TrailingZeros64(n)
		return t.levels[l][lo>>l]
	}
	k := largestPow2Less(n)
	return NodeHash(t.mth(lo, lo+k), t.mth(lo+k, hi))
}

// InclusionProof returns PATH(index, D[size]) per RFC 9162 §2.1.3.1.
func (t *Tree) InclusionProof(index, size uint64) ([]Hash, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if size > t.size() || index >= size {
		return nil, ErrBadRange
	}
	return t.path(index, 0, size, nil), nil
}

func (t *Tree) path(m, lo, hi uint64, acc []Hash) []Hash {
	n := hi - lo
	if n == 1 {
		return acc
	}
	k := largestPow2Less(n)
	if m-lo < k {
		acc = t.path(m, lo, lo+k, acc)
		return append(acc, t.mth(lo+k, hi))
	}
	acc = t.path(m, lo+k, hi, acc)
	return append(acc, t.mth(lo, lo+k))
}

// ConsistencyProof returns PROOF(m, D[n]) per RFC 9162 §2.1.4.1. For m == 0 or
// m == n the proof is empty.
func (t *Tree) ConsistencyProof(m, n uint64) ([]Hash, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if n > t.size() || m > n {
		return nil, ErrBadRange
	}
	if m == 0 || m == n {
		return []Hash{}, nil
	}
	return t.subproof(m, 0, n, true, nil), nil
}

func (t *Tree) subproof(m, lo, hi uint64, b bool, acc []Hash) []Hash {
	n := hi - lo
	if m == n {
		if b {
			return acc
		}
		return append(acc, t.mth(lo, hi))
	}
	k := largestPow2Less(n)
	if m <= k {
		acc = t.subproof(m, lo, lo+k, b, acc)
		return append(acc, t.mth(lo+k, hi))
	}
	acc = t.subproof(m-k, lo+k, hi, false, acc)
	return append(acc, t.mth(lo, lo+k))
}

// RootFromInclusion recomputes the root implied by an inclusion proof, per
// RFC 9162 §2.1.3.2. It fails if the proof has the wrong length for (index, size).
func RootFromInclusion(leaf Hash, index, size uint64, proof []Hash) (Hash, error) {
	if index >= size {
		return Hash{}, ErrBadRange
	}
	if len(proof) > MaxProofLen {
		return Hash{}, ErrInvalidProof
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return Hash{}, ErrInvalidProof
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return Hash{}, ErrInvalidProof
	}
	return r, nil
}

// VerifyInclusion checks that leaf is at index in the tree of the given size
// and root.
func VerifyInclusion(leaf Hash, index, size uint64, proof []Hash, root Hash) error {
	r, err := RootFromInclusion(leaf, index, size, proof)
	if err != nil {
		return err
	}
	if r != root {
		return ErrRootMismatch
	}
	return nil
}

// VerifyConsistency checks that the tree of size n with root newRoot is an
// append-only extension of the tree of size m with root oldRoot, per
// RFC 9162 §2.1.4.2. m == 0 is consistent with anything if the proof is empty
// and oldRoot is the empty root.
func VerifyConsistency(m, n uint64, oldRoot, newRoot Hash, proof []Hash) error {
	switch {
	case m > n:
		return ErrBadRange
	case m == 0:
		if len(proof) != 0 || oldRoot != EmptyRoot {
			return ErrInvalidProof
		}
		return nil
	case m == n:
		if len(proof) != 0 {
			return ErrInvalidProof
		}
		if oldRoot != newRoot {
			return ErrRootMismatch
		}
		return nil
	}
	if len(proof) == 0 || len(proof) > MaxProofLen {
		return ErrInvalidProof
	}
	p := proof
	if m&(m-1) == 0 { // m is an exact power of two
		p = append([]Hash{oldRoot}, proof...)
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := p[0], p[0]
	for _, c := range p[1:] {
		if sn == 0 {
			return ErrInvalidProof
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return ErrInvalidProof
	}
	if fr != oldRoot || sr != newRoot {
		return ErrRootMismatch
	}
	return nil
}
