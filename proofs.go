package tamperlog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/Aolost/tamperlog/checkpoint"
	"github.com/Aolost/tamperlog/entry"
	"github.com/Aolost/tamperlog/merkle"
	"github.com/Aolost/tamperlog/reason"
)

const bundleVersion = 1

var (
	inclusionMagic   = []byte("TLIP")
	consistencyMagic = []byte("TLCS")
	errBundle        = errors.New("tamperlog: malformed proof bundle")
)

// InclusionBundle is a self-contained, offline-verifiable proof that an entry
// is in a log at a signed tree head.
type InclusionBundle struct {
	Checkpoint *checkpoint.Checkpoint
	Entry      []byte // canonical entry encoding
	Index      uint64
	Size       uint64
	Proof      []merkle.Hash
}

// ConsistencyBundle proves that the log at New is an append-only extension of
// the log at Old.
type ConsistencyBundle struct {
	Old, New *checkpoint.Checkpoint
	Proof    []merkle.Hash
}

func appendBytes(b, v []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
	return append(b, v...)
}

func appendProof(b []byte, p []merkle.Hash) []byte {
	b = append(b, byte(len(p)))
	for _, h := range p {
		b = append(b, h[:]...)
	}
	return b
}

// MarshalBinary encodes the bundle (SPEC.md §9).
func (b *InclusionBundle) MarshalBinary() ([]byte, error) {
	if len(b.Proof) > merkle.MaxProofLen || b.Checkpoint == nil {
		return nil, errBundle
	}
	cb, _ := b.Checkpoint.MarshalBinary()
	out := append([]byte{}, inclusionMagic...)
	out = append(out, bundleVersion)
	out = appendBytes(out, cb)
	out = appendBytes(out, b.Entry)
	out = binary.BigEndian.AppendUint64(out, b.Index)
	out = binary.BigEndian.AppendUint64(out, b.Size)
	return appendProof(out, b.Proof), nil
}

// MarshalBinary encodes the bundle (SPEC.md §9).
func (b *ConsistencyBundle) MarshalBinary() ([]byte, error) {
	if len(b.Proof) > merkle.MaxProofLen || b.Old == nil || b.New == nil {
		return nil, errBundle
	}
	ob, _ := b.Old.MarshalBinary()
	nb, _ := b.New.MarshalBinary()
	out := append([]byte{}, consistencyMagic...)
	out = append(out, bundleVersion)
	out = appendBytes(out, ob)
	out = appendBytes(out, nb)
	return appendProof(out, b.Proof), nil
}

type reader struct {
	b   []byte
	err bool
}

func (r *reader) take(n int) []byte {
	if r.err || n < 0 || len(r.b) < n {
		r.err = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u32() uint32 {
	v := r.take(4)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

func (r *reader) u64() uint64 {
	v := r.take(8)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

func (r *reader) bytes(max uint32) []byte {
	n := r.u32()
	if n > max {
		r.err = true
		return nil
	}
	return r.take(int(n))
}

func (r *reader) checkpoint() *checkpoint.Checkpoint {
	b := r.bytes(checkpoint.Size)
	if r.err {
		return nil
	}
	cp, err := checkpoint.Unmarshal(b)
	if err != nil {
		r.err = true
	}
	return cp
}

func (r *reader) proof() []merkle.Hash {
	c := r.take(1)
	if c == nil || int(c[0]) > merkle.MaxProofLen {
		r.err = true
		return nil
	}
	p := make([]merkle.Hash, c[0])
	for i := range p {
		copy(p[i][:], r.take(merkle.HashSize))
	}
	return p
}

func (r *reader) header(magic []byte) {
	if !bytes.Equal(r.take(4), magic) {
		r.err = true
	}
	if v := r.take(1); v == nil || v[0] != bundleVersion {
		r.err = true
	}
}

// DecodeInclusionBundle strictly decodes an inclusion bundle.
func DecodeInclusionBundle(data []byte) (*InclusionBundle, error) {
	r := &reader{b: data}
	r.header(inclusionMagic)
	b := &InclusionBundle{}
	b.Checkpoint = r.checkpoint()
	b.Entry = bytes.Clone(r.bytes(entry.MaxEncodedSize))
	b.Index = r.u64()
	b.Size = r.u64()
	b.Proof = r.proof()
	if r.err || len(r.b) != 0 {
		return nil, errBundle
	}
	return b, nil
}

// DecodeConsistencyBundle strictly decodes a consistency bundle.
func DecodeConsistencyBundle(data []byte) (*ConsistencyBundle, error) {
	r := &reader{b: data}
	r.header(consistencyMagic)
	b := &ConsistencyBundle{}
	b.Old = r.checkpoint()
	b.New = r.checkpoint()
	b.Proof = r.proof()
	if r.err || len(r.b) != 0 {
		return nil, errBundle
	}
	return b, nil
}

func proofFail(code reason.Code, seq int64, detail string) *Finding {
	return &Finding{Reason: code, Seq: seq, Offset: -1, Detail: detail}
}

// Verify checks the bundle against pub and returns the proven entry.
func (b *InclusionBundle) Verify(pub ed25519.PublicKey) (*entry.Entry, *Finding) {
	if err := b.Checkpoint.Verify(pub); err != nil {
		return nil, &Finding{Reason: reason.CheckpointSignature, Seq: -1, Offset: -1, File: "proof", Detail: "checkpoint in proof does not verify"}
	}
	e, err := entry.Unmarshal(b.Entry)
	if err != nil {
		return nil, proofFail(reason.ProofDecode, int64(b.Index), "entry: "+err.Error())
	}
	if e.Seq != b.Index {
		return nil, proofFail(reason.ProofInvalid, int64(b.Index), fmt.Sprintf("entry seq %d does not match proof index %d", e.Seq, b.Index))
	}
	if b.Size != b.Checkpoint.TreeSize {
		return nil, proofFail(reason.ProofInvalid, int64(b.Index), fmt.Sprintf("proof size %d does not match checkpoint size %d", b.Size, b.Checkpoint.TreeSize))
	}
	if err := merkle.VerifyInclusion(entry.Hash(b.Entry), b.Index, b.Size, b.Proof, b.Checkpoint.Root); err != nil {
		return nil, proofFail(reason.ProofInvalid, int64(b.Index), err.Error())
	}
	return &e, nil
}

// Verify checks both checkpoints against pub and the consistency proof.
func (b *ConsistencyBundle) Verify(pub ed25519.PublicKey) *Finding {
	for _, c := range []struct {
		cp   *checkpoint.Checkpoint
		name string
	}{{b.Old, "old"}, {b.New, "new"}} {
		if err := c.cp.Verify(pub); err != nil {
			return &Finding{Reason: reason.CheckpointSignature, Seq: -1, Offset: -1, File: c.name, Detail: c.name + " checkpoint does not verify"}
		}
	}
	if b.Old.LogID != b.New.LogID {
		return &Finding{Reason: reason.CheckpointLogID, Seq: -1, Offset: -1, File: "new", Detail: "checkpoints belong to different logs"}
	}
	if err := merkle.VerifyConsistency(b.Old.TreeSize, b.New.TreeSize, b.Old.Root, b.New.Root, b.Proof); err != nil {
		return proofFail(reason.ProofInvalid, int64(b.Old.TreeSize), fmt.Sprintf("size %d -> %d: %v", b.Old.TreeSize, b.New.TreeSize, err))
	}
	return nil
}

// ProveInclusion builds an inclusion bundle for entry seq against cp, which
// must be a checkpoint of this log that matches its contents.
func (l *Log) ProveInclusion(seq uint64, cp *checkpoint.Checkpoint) (*InclusionBundle, error) {
	if err := l.matches(cp); err != nil {
		return nil, err
	}
	if seq >= cp.TreeSize {
		return nil, fmt.Errorf("%w: seq %d not covered by checkpoint of size %d", ErrRange, seq, cp.TreeSize)
	}
	eb, err := l.EntryBytes(seq)
	if err != nil {
		return nil, err
	}
	p, err := l.InclusionProof(seq, cp.TreeSize)
	if err != nil {
		return nil, err
	}
	return &InclusionBundle{Checkpoint: cp, Entry: eb, Index: seq, Size: cp.TreeSize, Proof: p}, nil
}

// ProveConsistency builds a consistency bundle between two checkpoints of
// this log.
func (l *Log) ProveConsistency(old, new *checkpoint.Checkpoint) (*ConsistencyBundle, error) {
	for _, c := range []*checkpoint.Checkpoint{old, new} {
		if err := l.matches(c); err != nil {
			return nil, err
		}
	}
	if old.TreeSize > new.TreeSize {
		return nil, fmt.Errorf("%w: old size %d > new size %d", ErrRange, old.TreeSize, new.TreeSize)
	}
	p, err := l.ConsistencyProof(old.TreeSize, new.TreeSize)
	if err != nil {
		return nil, err
	}
	return &ConsistencyBundle{Old: old, New: new, Proof: p}, nil
}

func (l *Log) matches(cp *checkpoint.Checkpoint) error {
	if cp.LogID != l.logID {
		return &Finding{Reason: reason.CheckpointLogID, Seq: -1, Offset: -1, Detail: "checkpoint belongs to another log"}
	}
	root, err := l.RootAt(cp.TreeSize)
	if err != nil {
		return &Finding{Reason: reason.WitnessRollback, Seq: int64(l.Size()), Offset: -1, Detail: "checkpoint is larger than the log"}
	}
	if root != cp.Root {
		return &Finding{Reason: reason.CheckpointRootMismatch, Seq: -1, Offset: -1, Detail: "checkpoint root does not match this log"}
	}
	return nil
}
