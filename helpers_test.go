package tamperlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Aolost/tamperlog/checkpoint"
	"github.com/Aolost/tamperlog/entry"
	"github.com/Aolost/tamperlog/merkle"
	"github.com/Aolost/tamperlog/storage"
)

// fakeClock returns strictly increasing, even nanosecond timestamps, so a
// low-bit flip always moves a timestamp forward by exactly 1ns.
func fakeClock() func() time.Time {
	var n atomic.Int64
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	return func() time.Time { return time.Unix(0, base+n.Add(1)*1000) }
}

type fixture struct {
	t    *testing.T
	dir  string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	id   [32]byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := filepath.Join(t.TempDir(), "log")
	id, err := Create(dir, pub, "")
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, dir: dir, pub: pub, priv: priv, id: id}
}

func (f *fixture) opts() Options {
	return Options{Signer: f.priv, Sync: SyncNone, CheckpointEvery: 1, Now: fakeClock()}
}

func (f *fixture) open(o Options) *Log {
	f.t.Helper()
	l, err := Open(f.dir, o)
	if err != nil {
		f.t.Fatal(err)
	}
	return l
}

// build creates a log with n entries and a checkpoint after every append.
func (f *fixture) build(n int) *fixture {
	f.t.Helper()
	l := f.open(f.opts())
	for i := 0; i < n; i++ {
		if _, err := l.Append([]byte(fmt.Sprintf("event-%d payload", i))); err != nil {
			f.t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		f.t.Fatal(err)
	}
	return f
}

func (f *fixture) verify(w *checkpoint.Checkpoint) *Report {
	f.t.Helper()
	r, err := Verify(f.dir, VerifyOptions{PublicKey: f.pub, Witness: w})
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *fixture) checkpointAt(size uint64) *checkpoint.Checkpoint {
	f.t.Helper()
	cp, err := checkpoint.ReadFile(filepath.Join(f.dir, CheckpointDir, checkpointName(size)))
	if err != nil {
		f.t.Fatal(err)
	}
	return cp
}

// frameRef locates a frame in the (single) segment.
type frameRef struct {
	seg      string
	off      int
	size     int
	entryLen int
}

func (f *fixture) frames() []frameRef {
	f.t.Helper()
	var out []frameRef
	_, err := storage.Scan(f.dir, func(r storage.Record) error {
		out = append(out, frameRef{seg: r.Segment, off: int(r.Offset), size: storage.FrameSize(len(r.Entry)), entryLen: len(r.Entry)})
		return nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *fixture) segPath(name string) string { return filepath.Join(f.dir, storage.SegmentDir, name) }

func (f *fixture) readSeg(name string) []byte {
	b, err := os.ReadFile(f.segPath(name))
	if err != nil {
		f.t.Fatal(err)
	}
	return b
}

func (f *fixture) writeSeg(name string, b []byte) {
	if err := os.WriteFile(f.segPath(name), b, 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// Field offsets inside a frame.
const (
	offLen     = 0
	offCRC     = 4
	offVersion = storage.HeaderSize
	offSeq     = offVersion + 1
	offTS      = offSeq + 8
	offPrev    = offTS + 8
	offPLen    = offPrev + merkle.HashSize
	offPayload = offPLen + 4
)

// fixHash recomputes the stored entry hash of a frame (attacker capability).
func fixHash(frame []byte) {
	n := len(frame) - storage.Overhead
	h := entry.Hash(frame[storage.HeaderSize : storage.HeaderSize+n])
	copy(frame[storage.HeaderSize+n:], h[:])
}

// frameHash returns the stored hash of a frame.
func frameHash(frame []byte) merkle.Hash {
	var h merkle.Hash
	copy(h[:], frame[len(frame)-merkle.HashSize:])
	return h
}

// rechain rewrites prev_hash links (and hashes and CRCs) of every frame after
// index from, modelling an attacker who recomputes the whole chain.
func (f *fixture) rechain(from int) {
	fr := f.frames()
	b := f.readSeg(fr[0].seg)
	for i := from + 1; i < len(fr); i++ {
		prev := frameHash(b[fr[i-1].off : fr[i-1].off+fr[i-1].size])
		cur := b[fr[i].off : fr[i].off+fr[i].size]
		copy(cur[offPrev:offPrev+merkle.HashSize], prev[:])
		fixHash(cur)
		storage.FixCRC(cur)
	}
	f.writeSeg(fr[0].seg, b)
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	if out, err := exec.Command("cp", "-a", src, dst).CombinedOutput(); err != nil {
		t.Fatalf("cp: %v %s", err, out)
	}
}

func mustEqual(t *testing.T, a, b []byte) {
	t.Helper()
	if !bytes.Equal(a, b) {
		t.Fatalf("bytes differ")
	}
}

func genKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func seedKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)) }

func seedInclusionBundle() []byte {
	e := entry.Entry{Seq: 1, Timestamp: 5, Payload: []byte("seed")}
	eb := e.AppendBinary(nil)
	cp := checkpoint.Sign(seedKey(), [32]byte{1}, 2, merkle.NodeHash(merkle.Hash{}, entry.Hash(eb)), time.Unix(0, 9))
	b, _ := (&InclusionBundle{Checkpoint: cp, Entry: eb, Index: 1, Size: 2, Proof: []merkle.Hash{{}}}).MarshalBinary()
	return b
}

func seedConsistencyBundle() []byte {
	a := checkpoint.Sign(seedKey(), [32]byte{1}, 1, merkle.Hash{1}, time.Unix(0, 9))
	c := checkpoint.Sign(seedKey(), [32]byte{1}, 2, merkle.Hash{2}, time.Unix(0, 10))
	b, _ := (&ConsistencyBundle{Old: a, New: c, Proof: []merkle.Hash{{3}}}).MarshalBinary()
	return b
}
