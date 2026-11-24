// Package tamperlog is a tamper-evident, append-only audit log. It combines
// a hash chain, an RFC 6962 Merkle tree with inclusion and consistency proofs,
// and Ed25519-signed checkpoints. See SPEC.md and THREAT_MODEL.md.
//
// A *Log is the single writer for a directory (enforced by flock). It is safe
// for one appending goroutine and many concurrent readers. Use Verify to check
// a log from another process without trusting the machine that wrote it.
package tamperlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Aolost/tamperlog/checkpoint"
	"github.com/Aolost/tamperlog/entry"
	"github.com/Aolost/tamperlog/merkle"
	"github.com/Aolost/tamperlog/reason"
	"github.com/Aolost/tamperlog/storage"
)

// Directory layout.
const (
	MetaFile      = "meta.json"
	PubKeyFile    = "pubkey.pem"
	CheckpointDir = "checkpoints"
	checkpointExt = ".ck"
	FormatVersion = 1
)

// SyncPolicy controls when appends are fsynced.
type SyncPolicy int

const (
	// SyncEvery fsyncs after every append. An acknowledged entry survives
	// power loss. This is the default.
	SyncEvery SyncPolicy = iota
	// SyncBatch fsyncs every BatchSize appends and on Sync/Checkpoint/Close.
	// RISK: up to BatchSize-1 acknowledged entries can be lost on power
	// failure. Recovery stays consistent (only a suffix is lost).
	SyncBatch
	// SyncNone never fsyncs explicitly. For tests and benchmarks only.
	SyncNone
)

// Options configures Open.
type Options struct {
	// Signer signs checkpoints. Without it, Checkpoint fails.
	Signer ed25519.PrivateKey
	// Sync is the fsync policy (default SyncEvery).
	Sync SyncPolicy
	// BatchSize is the fsync interval for SyncBatch (default 64).
	BatchSize int
	// SegmentSize is the segment roll-over size (default 64 MiB).
	SegmentSize int64
	// CheckpointEvery signs a checkpoint every N entries (0 = manual only).
	// Requires Signer.
	CheckpointEvery uint64
	// Logger receives warnings (torn-tail recovery). Never receives key material.
	Logger *slog.Logger
	// Now is the clock (default time.Now).
	Now func() time.Time
	// WrapFile wraps segment files opened for writing (crash-test hook).
	WrapFile func(storage.WriteFile) storage.WriteFile
	// ReadOnly opens the log without the writer lock, for proofs and export
	// alongside a running writer. Nothing is modified on disk: a torn tail is
	// ignored rather than truncated. Append and Checkpoint fail.
	ReadOnly bool
}

// Meta is the content of meta.json. It is not trusted by the verifier.
type Meta struct {
	Version int    `json:"version"`
	LogID   string `json:"log_id"`
	KeyPath string `json:"key_path,omitempty"`
	Created string `json:"created"`
}

// Errors.
var (
	ErrPoisoned = errors.New("tamperlog: writer failed earlier; reopen the log to recover")
	ErrClosed   = errors.New("tamperlog: log closed")
	ErrNoSigner = errors.New("tamperlog: no signing key configured")
	ErrExists   = errors.New("tamperlog: log already initialized")
	ErrRange    = errors.New("tamperlog: sequence number or size out of range")
	ErrLocked   = storage.ErrLocked
	ErrReadOnly = errors.New("tamperlog: log opened read-only")
)

// Create initializes a new, empty log in dir. pub is the checkpoint
// verification key (a copy is stored in dir for convenience only). keyPath is
// recorded so the CLI can find the private key; it may be empty.
func Create(dir string, pub ed25519.PublicKey, keyPath string) ([32]byte, error) {
	var id [32]byte
	if _, err := os.Stat(filepath.Join(dir, MetaFile)); err == nil {
		return id, ErrExists
	}
	for _, d := range []string{dir, filepath.Join(dir, storage.SegmentDir), filepath.Join(dir, CheckpointDir)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return id, err
		}
	}
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	m := Meta{Version: FormatVersion, LogID: hex.EncodeToString(id[:]), KeyPath: keyPath, Created: time.Now().UTC().Format(time.RFC3339)}
	mb, _ := json.MarshalIndent(m, "", "  ")
	if pub != nil {
		pb, err := checkpoint.MarshalPublicKey(pub)
		if err != nil {
			return id, err
		}
		if err := checkpoint.WriteFileAtomic(filepath.Join(dir, PubKeyFile), pb, 0o644); err != nil {
			return id, err
		}
	}
	return id, checkpoint.WriteFileAtomic(filepath.Join(dir, MetaFile), append(mb, '\n'), 0o644)
}

// ReadMeta reads meta.json.
func ReadMeta(dir string) (*Meta, [32]byte, error) {
	var id [32]byte
	b, err := os.ReadFile(filepath.Join(dir, MetaFile))
	if err != nil {
		return nil, id, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, id, fmt.Errorf("tamperlog: bad %s: %w", MetaFile, err)
	}
	raw, err := hex.DecodeString(m.LogID)
	if err != nil || len(raw) != 32 || m.Version != FormatVersion {
		return nil, id, fmt.Errorf("tamperlog: bad %s: invalid log_id or version", MetaFile)
	}
	copy(id[:], raw)
	return &m, id, nil
}

// Log is an open, writable tamperlog.
type Log struct {
	mu       sync.RWMutex
	dir      string
	opts     Options
	logID    [32]byte
	lock     *storage.Lock
	w        *storage.Writer
	tree     *merkle.Tree
	locs     []loc
	segs     []string
	readers  []*os.File
	head     merkle.Hash
	lastTS   int64
	unsynced int
	poisoned error
	closed   bool
	latestCP *checkpoint.Checkpoint
}

// Open opens the log in dir as its single writer, running crash recovery:
// a torn trailing record is truncated with a warning; any other corruption
// makes Open fail with a *CorruptionError that names the reason and offset.
func Open(dir string, opts Options) (*Log, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 64
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	_, id, err := ReadMeta(dir)
	if err != nil {
		return nil, err
	}
	var lock *storage.Lock
	if !opts.ReadOnly {
		if lock, err = storage.LockExclusive(dir); err != nil {
			return nil, err
		}
	}
	l := &Log{dir: dir, opts: opts, logID: id, lock: lock}
	if err := l.recover(); err != nil {
		l.closeFiles()
		lock.Release()
		return nil, err
	}
	return l, nil
}

func (l *Log) recover() error {
	// Leftover temp files from an interrupted checkpoint write are garbage.
	tmps, _ := filepath.Glob(filepath.Join(l.dir, CheckpointDir, "*.tmp"))
	if len(tmps) > 0 && !l.opts.ReadOnly {
		for _, t := range tmps {
			os.Remove(t)
		}
		l.opts.Logger.Warn("removed incomplete checkpoint temp files", "count", len(tmps))
	}
	// Checkpoints are read before segments (see Verify): a concurrent writer
	// makes data durable before signing it, so this order has no false alarms.
	cps, err := readCheckpoints(l.dir)
	if err != nil {
		return err
	}
	s, finding, err := scanEntries(l.dir, l.logID)
	if err != nil {
		return err
	}
	if finding != nil {
		return &CorruptionError{*finding}
	}
	if t := s.res.Torn; t != nil && !l.opts.ReadOnly {
		if err := storage.TruncateTorn(l.dir, t); err != nil {
			return err
		}
		l.opts.Logger.Warn("truncated torn trailing record", "segment", t.Segment, "offset", t.Offset, "bytes", t.Bytes, "seq", t.Index)
	}
	l.tree, l.locs, l.segs, l.head, l.lastTS = s.tree, s.locs, s.segs, s.head, s.lastTS
	for _, name := range l.segs {
		if err := l.openReader(name); err != nil {
			return err
		}
	}
	if err := l.checkLatestCheckpoint(cps); err != nil {
		return err
	}
	if l.opts.ReadOnly {
		return nil
	}
	var last storage.SegmentInfo
	if n := len(s.res.Segments); n > 0 {
		last = s.res.Segments[n-1]
	}
	l.w, err = storage.NewWriter(l.dir, last, l.tree.Size(), storage.WriterOptions{SegmentSize: l.opts.SegmentSize, WrapFile: l.opts.WrapFile}, l.onNewSegment)
	return err
}

// checkLatestCheckpoint refuses to continue a log whose newest local
// checkpoint does not match the data (entries a signature vouched for are
// gone or different).
func (l *Log) checkLatestCheckpoint(cps []cpFile) error {
	// Checkpoints are written atomically, so a crash never leaves a malformed
	// one under its final name: any malformed file is tampering or disk damage.
	for _, c := range cps {
		if c.err != nil {
			return &CorruptionError{Finding{Reason: reason.CheckpointDecode, Seq: -1, Offset: -1, File: c.name, Detail: c.err.Error()}}
		}
	}
	for i := len(cps) - 1; i >= 0; i-- {
		c := cps[i]
		if l.opts.Signer != nil {
			if err := c.cp.Verify(l.opts.Signer.Public().(ed25519.PublicKey)); err != nil {
				return &CorruptionError{Finding{Reason: reason.CheckpointSignature, Seq: -1, Offset: -1, File: c.name, Detail: err.Error()}}
			}
		}
		if c.cp.LogID != l.logID {
			return &CorruptionError{Finding{Reason: reason.CheckpointLogID, Seq: -1, Offset: -1, File: c.name, Detail: "checkpoint belongs to another log"}}
		}
		n := l.tree.Size()
		if c.cp.TreeSize > n {
			return &CorruptionError{Finding{Reason: reason.LogTruncated, Seq: int64(n), Offset: -1, File: c.name,
				Detail: fmt.Sprintf("checkpoint covers %d entries, log has %d", c.cp.TreeSize, n)}}
		}
		root, _ := l.tree.RootAt(c.cp.TreeSize)
		if root != c.cp.Root {
			return &CorruptionError{Finding{Reason: reason.CheckpointRootMismatch, Seq: -1, Offset: -1, File: c.name, Detail: "signed root does not match log contents"}}
		}
		l.latestCP = c.cp
		return nil
	}
	return nil
}

func (l *Log) openReader(name string) error {
	f, err := os.Open(filepath.Join(l.dir, storage.SegmentDir, name))
	if err != nil {
		return err
	}
	l.readers = append(l.readers, f)
	return nil
}

// onNewSegment is called by the writer (under l.mu) when it creates a segment.
func (l *Log) onNewSegment(name string) {
	if err := l.openReader(name); err != nil {
		l.poisoned = err
		return
	}
	l.segs = append(l.segs, name)
}

// LogID returns the log's random identifier.
func (l *Log) LogID() [32]byte { return l.logID }

// Dir returns the log directory.
func (l *Log) Dir() string { return l.dir }

// Size returns the number of entries.
func (l *Log) Size() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.tree.Size()
}

// Root returns the current Merkle root.
func (l *Log) Root() merkle.Hash {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.tree.Root()
}

// RootAt returns the Merkle root of the first n entries.
func (l *Log) RootAt(n uint64) (merkle.Hash, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.tree.RootAt(n)
}

// Append adds one entry and returns its sequence number.
func (l *Log) Append(payload []byte) (uint64, error) {
	seq, err := l.AppendBatch([][]byte{payload})
	return seq, err
}

// AppendBatch adds several entries with at most one fsync (under SyncEvery)
// and returns the sequence number of the first.
func (l *Log) AppendBatch(payloads [][]byte) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.usable(); err != nil {
		return 0, err
	}
	for _, p := range payloads {
		if len(p) > entry.MaxPayload {
			return 0, entry.ErrTooLarge
		}
	}
	first := l.tree.Size()
	var buf []byte
	for _, p := range payloads {
		ts := l.opts.Now().UnixNano()
		if ts < l.lastTS {
			ts = l.lastTS // timestamps never go backwards
		}
		e := entry.Entry{Seq: l.tree.Size(), Timestamp: ts, PrevHash: l.head, Payload: p}
		eb := e.AppendBinary(nil)
		h := entry.Hash(eb)
		buf = storage.AppendFrame(buf[:0], eb, h)
		seg, off, err := l.w.Append(buf)
		if err != nil {
			l.poisoned = err
			return 0, fmt.Errorf("tamperlog: append: %w", err)
		}
		if l.poisoned != nil {
			return 0, l.poisoned
		}
		l.locs = append(l.locs, loc{seg: l.segIndex(seg), off: off, n: uint32(len(eb))})
		l.tree.AppendLeafHash(h)
		l.head, l.lastTS = h, ts
		l.unsynced++
		if l.opts.Sync == SyncBatch && l.unsynced >= l.opts.BatchSize {
			if err := l.syncLocked(); err != nil {
				return 0, err
			}
		}
	}
	if l.opts.Sync == SyncEvery {
		if err := l.syncLocked(); err != nil {
			return 0, err
		}
	}
	if every := l.opts.CheckpointEvery; every > 0 && l.opts.Signer != nil {
		n := l.tree.Size()
		if n/every != first/every {
			if _, err := l.checkpointLocked(); err != nil {
				return 0, err
			}
		}
	}
	return first, nil
}

func (l *Log) segIndex(name string) uint32 {
	for i := len(l.segs) - 1; i >= 0; i-- {
		if l.segs[i] == name {
			return uint32(i)
		}
	}
	panic("tamperlog: unknown segment " + name)
}

func (l *Log) usable() error {
	if l.closed {
		return ErrClosed
	}
	if l.w == nil {
		return ErrReadOnly
	}
	if l.poisoned != nil {
		return fmt.Errorf("%w (%v)", ErrPoisoned, l.poisoned)
	}
	return nil
}

func (l *Log) syncLocked() error {
	if l.opts.Sync == SyncNone {
		l.unsynced = 0
		return nil
	}
	if err := l.w.Sync(); err != nil {
		l.poisoned = err
		return fmt.Errorf("tamperlog: fsync: %w", err)
	}
	l.unsynced = 0
	return nil
}

// Sync forces an fsync of pending appends.
func (l *Log) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.usable(); err != nil {
		return err
	}
	if l.opts.Sync == SyncNone {
		if err := l.w.Sync(); err != nil {
			l.poisoned = err
			return err
		}
		return nil
	}
	return l.syncLocked()
}

// Checkpoint fsyncs pending entries, signs the current tree head, writes it
// to checkpoints/ atomically, and returns it. A checkpoint never covers data
// that is not durable.
func (l *Log) Checkpoint() (*checkpoint.Checkpoint, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.usable(); err != nil {
		return nil, err
	}
	return l.checkpointLocked()
}

func (l *Log) checkpointLocked() (*checkpoint.Checkpoint, error) {
	if l.opts.Signer == nil {
		return nil, ErrNoSigner
	}
	if err := l.w.Sync(); err != nil {
		l.poisoned = err
		return nil, err
	}
	l.unsynced = 0
	ts := l.opts.Now()
	if ts.UnixNano() < l.lastTS {
		ts = time.Unix(0, l.lastTS)
	}
	cp := checkpoint.Sign(l.opts.Signer, l.logID, l.tree.Size(), l.tree.Root(), ts)
	b, _ := cp.MarshalBinary()
	if err := os.MkdirAll(filepath.Join(l.dir, CheckpointDir), 0o755); err != nil {
		return nil, err
	}
	if err := checkpoint.WriteFileAtomic(filepath.Join(l.dir, CheckpointDir, checkpointName(cp.TreeSize)), b, 0o644); err != nil {
		return nil, err
	}
	l.latestCP = cp
	return cp, nil
}

// LatestCheckpoint returns the newest checkpoint written or verified by this
// writer, or nil.
func (l *Log) LatestCheckpoint() *checkpoint.Checkpoint {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.latestCP
}

// EntryBytes returns the canonical encoding of entry seq, read from disk and
// checked against the in-memory leaf hash.
func (l *Log) EntryBytes(seq uint64) ([]byte, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return nil, ErrClosed
	}
	if seq >= uint64(len(l.locs)) {
		return nil, ErrRange
	}
	lc := l.locs[seq]
	fr, err := storage.ReadFrameAt(l.readers[lc.seg], lc.off, int(lc.n))
	if err != nil {
		return nil, err
	}
	want, _ := l.tree.LeafHash(seq)
	if entry.Hash(fr.Entry) != want {
		return nil, &Finding{Reason: reason.EntryHashMismatch, Seq: int64(seq), Segment: l.segs[lc.seg], Offset: lc.off, Detail: "entry changed on disk while the log was open"}
	}
	return bytes.Clone(fr.Entry), nil
}

// Entry returns entry seq.
func (l *Log) Entry(seq uint64) (entry.Entry, error) {
	b, err := l.EntryBytes(seq)
	if err != nil {
		return entry.Entry{}, err
	}
	return entry.Unmarshal(b)
}

// InclusionProof proves entry seq is in the tree of the given size.
func (l *Log) InclusionProof(seq, size uint64) ([]merkle.Hash, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.tree.InclusionProof(seq, size)
}

// ConsistencyProof proves the tree of size m is a prefix of the tree of size n.
func (l *Log) ConsistencyProof(m, n uint64) ([]merkle.Hash, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.tree.ConsistencyProof(m, n)
}

// Close fsyncs and releases the log and its lock.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	var err error
	if l.w != nil {
		err = l.w.Close()
	}
	l.closeFiles()
	if rerr := l.lock.Release(); err == nil {
		err = rerr
	}
	return err
}

func (l *Log) closeFiles() {
	for _, f := range l.readers {
		f.Close()
	}
	l.readers = nil
}
