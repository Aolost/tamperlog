package tamperlog

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Aolost/tamperlog/checkpoint"
	"github.com/Aolost/tamperlog/entry"
	"github.com/Aolost/tamperlog/merkle"
	"github.com/Aolost/tamperlog/reason"
)

// One writer, many readers, plus a cross-process style verifier, all at once.
// Run under -race.
func TestConcurrentWriterReaders(t *testing.T) {
	f := newFixture(t)
	l := f.open(f.opts())
	defer l.Close()
	const total = 400
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan error, 16)
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for {
				select {
				case <-stop:
					return
				default:
				}
				n := l.Size()
				if n == 0 {
					continue
				}
				seq := uint64(rng.Int63n(int64(n)))
				b, err := l.EntryBytes(seq)
				if err != nil {
					errs <- err
					return
				}
				root, err := l.RootAt(n)
				if err != nil {
					errs <- err
					return
				}
				p, err := l.InclusionProof(seq, n)
				if err != nil || merkle.VerifyInclusion(entry.Hash(b), seq, n, p, root) != nil {
					errs <- fmt.Errorf("inclusion %d/%d: %v", seq, n, err)
					return
				}
				m := uint64(rng.Int63n(int64(n))) + 1
				old, _ := l.RootAt(m)
				cp, err := l.ConsistencyProof(m, n)
				if err != nil || merkle.VerifyConsistency(m, n, old, root, cp) != nil {
					errs <- fmt.Errorf("consistency %d/%d: %v", m, n, err)
					return
				}
			}
		}(int64(r))
	}
	wg.Add(1)
	go func() { // verifier from "another process" while the writer is live
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			r, err := Verify(f.dir, VerifyOptions{PublicKey: f.pub})
			if err != nil {
				errs <- err
				return
			}
			if !r.OK || !r.Live {
				errs <- fmt.Errorf("live verify: %s live=%v", r, r.Live)
				return
			}
		}
	}()
	for i := 0; i < total; i++ {
		if _, err := l.Append([]byte(fmt.Sprintf("concurrent-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if l.Size() != total {
		t.Fatal("size")
	}
}

func TestSingleWriterLock(t *testing.T) {
	f := newFixture(t)
	l := f.open(f.opts())
	if _, err := Open(f.dir, f.opts()); !errors.Is(err, ErrLocked) {
		t.Fatalf("second writer: %v", err)
	}
	l.Close()
	l2 := f.open(f.opts())
	l2.Close()
	if err := l2.Close(); err != nil {
		t.Fatal("double close")
	}
}

func TestLogAPI(t *testing.T) {
	f := newFixture(t)
	if _, err := Create(f.dir, f.pub, ""); !errors.Is(err, ErrExists) {
		t.Fatal("create twice")
	}
	l := f.open(Options{Sync: SyncEvery})
	if l.Dir() != f.dir || l.LogID() != f.id {
		t.Fatal("accessors")
	}
	if _, err := l.Checkpoint(); !errors.Is(err, ErrNoSigner) {
		t.Fatal("no signer")
	}
	seq, err := l.AppendBatch([][]byte{[]byte("a"), []byte("b")})
	if err != nil || seq != 0 || l.Size() != 2 {
		t.Fatal("batch")
	}
	if _, err := l.Append(make([]byte, entry.MaxPayload+1)); !errors.Is(err, entry.ErrTooLarge) {
		t.Fatal("too large")
	}
	if _, err := l.Entry(2); !errors.Is(err, ErrRange) {
		t.Fatal("range")
	}
	if err := l.Sync(); err != nil {
		t.Fatal(err)
	}
	if l.LatestCheckpoint() != nil {
		t.Fatal("no checkpoint yet")
	}
	l.Close()
	if _, err := l.Append(nil); !errors.Is(err, ErrClosed) {
		t.Fatal("closed append")
	}
	if _, err := l.EntryBytes(0); !errors.Is(err, ErrClosed) {
		t.Fatal("closed read")
	}
	if err := l.Sync(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed sync")
	}
	if _, err := l.Checkpoint(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed checkpoint")
	}

	// Timestamps never go backwards even if the clock does.
	back := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := []time.Time{back.Add(time.Hour), back}
	i := 0
	l = f.open(Options{Signer: f.priv, Sync: SyncNone, Now: func() time.Time { t := clock[i%2]; i++; return t }})
	l.Append([]byte("c"))
	l.Append([]byte("d"))
	e2, _ := l.Entry(2)
	e3, _ := l.Entry(3)
	if e3.Timestamp < e2.Timestamp {
		t.Fatal("timestamp regressed")
	}
	cp, err := l.Checkpoint()
	if err != nil || cp.Timestamp < e3.Timestamp || l.LatestCheckpoint() != cp {
		t.Fatal("checkpoint timestamp")
	}
	if err := l.Sync(); err != nil {
		t.Fatal(err)
	}
	l.Close()

	// Batched mode syncs on BatchSize.
	l = f.open(Options{Signer: f.priv, Sync: SyncBatch, BatchSize: 2, CheckpointEvery: 3})
	for i := 0; i < 5; i++ {
		l.Append([]byte("e"))
	}
	if l.LatestCheckpoint().TreeSize != 9 {
		t.Fatalf("auto checkpoint at %d", l.LatestCheckpoint().TreeSize)
	}
	l.Close()
	if r := f.verify(nil); !r.OK || r.UnsignedTail != 0 {
		t.Fatal(r)
	}
}

func TestOpenErrors(t *testing.T) {
	if _, err := Open(t.TempDir(), Options{}); err == nil {
		t.Fatal("open without meta")
	}
	f := newFixture(t)
	os.WriteFile(filepath.Join(f.dir, MetaFile), []byte("{"), 0o644)
	if _, err := Open(f.dir, Options{}); err == nil {
		t.Fatal("bad meta json")
	}
	os.WriteFile(filepath.Join(f.dir, MetaFile), []byte(`{"version":1,"log_id":"abc"}`), 0o644)
	if _, err := Open(f.dir, Options{}); err == nil {
		t.Fatal("bad log id")
	}
	if _, err := Verify(f.dir, VerifyOptions{}); err == nil {
		t.Fatal("verify bad meta")
	}
	g := newFixture(t).build(1)
	os.Remove(filepath.Join(g.dir, PubKeyFile))
	if _, err := Verify(g.dir, VerifyOptions{}); err == nil {
		t.Fatal("verify without any key")
	}
	// Writer whose signer is not the key that signed the checkpoints.
	_, other, _ := genKey()
	if _, err := Open(g.dir, Options{Signer: other}); err == nil {
		t.Fatal("foreign signer accepted")
	} else {
		var ce *CorruptionError
		if !errors.As(err, &ce) || ce.Reason != reason.CheckpointSignature {
			t.Fatal(err)
		}
	}
}

func TestProofBundles(t *testing.T) {
	f := newFixture(t).build(20)
	l := f.open(f.opts())
	defer l.Close()
	cp20 := l.LatestCheckpoint()
	cp7 := f.checkpointAt(7)

	ib, err := l.ProveInclusion(5, cp20)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := ib.MarshalBinary()
	d, err := DecodeInclusionBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	e, fd := d.Verify(f.pub)
	if fd != nil || e.Seq != 5 {
		t.Fatal(fd)
	}
	// Every single-byte mutation must fail decode or verification.
	for i := range b {
		for _, x := range []byte{0x01, 0xFF} {
			m := append([]byte(nil), b...)
			m[i] ^= x
			d, err := DecodeInclusionBundle(m)
			if err != nil {
				continue
			}
			if _, fd := d.Verify(f.pub); fd == nil {
				t.Fatalf("inclusion bundle mutation at byte %d ^%x accepted", i, x)
			}
		}
	}
	if _, err := DecodeInclusionBundle(append(b, 0)); err == nil {
		t.Fatal("trailing byte")
	}
	if _, err := DecodeInclusionBundle(b[:len(b)-1]); err == nil {
		t.Fatal("short")
	}

	cb, err := l.ProveConsistency(cp7, cp20)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = cb.MarshalBinary()
	dc, err := DecodeConsistencyBundle(b)
	if err != nil || dc.Verify(f.pub) != nil {
		t.Fatal("consistency")
	}
	for i := range b {
		m := append([]byte(nil), b...)
		m[i] ^= 0x01
		if d, err := DecodeConsistencyBundle(m); err == nil && d.Verify(f.pub) == nil {
			t.Fatalf("consistency mutation at byte %d accepted", i)
		}
	}
	if _, err := l.ProveConsistency(cp20, cp7); err == nil {
		t.Fatal("old > new")
	}
	if _, err := l.ProveInclusion(20, cp20); !errors.Is(err, ErrRange) {
		t.Fatal("seq beyond checkpoint")
	}
	foreign := checkpoint.Sign(f.priv, [32]byte{1}, 3, cp7.Root, time.Now())
	if _, err := l.ProveInclusion(1, foreign); err == nil {
		t.Fatal("foreign checkpoint")
	}
	big := checkpoint.Sign(f.priv, f.id, 99, cp7.Root, time.Now())
	if _, err := l.ProveInclusion(1, big); err == nil {
		t.Fatal("checkpoint larger than log")
	}
	wrong := checkpoint.Sign(f.priv, f.id, 7, cp20.Root, time.Now())
	if _, err := l.ProveConsistency(wrong, cp20); err == nil {
		t.Fatal("wrong root")
	}
	// Mismatched logs in a consistency bundle.
	bad := &ConsistencyBundle{Old: foreign, New: cp20, Proof: cb.Proof}
	if fd := bad.Verify(f.pub); fd == nil || fd.Reason != reason.CheckpointLogID {
		t.Fatal("log id mismatch")
	}
	if _, err := (&InclusionBundle{}).MarshalBinary(); err == nil {
		t.Fatal("nil checkpoint")
	}
	if _, err := (&ConsistencyBundle{}).MarshalBinary(); err == nil {
		t.Fatal("nil checkpoints")
	}
	// Bundle whose size disagrees with its checkpoint.
	ib.Size = 19
	if _, fd := ib.Verify(f.pub); fd == nil || fd.Reason != reason.ProofInvalid {
		t.Fatal("size mismatch")
	}
}

func FuzzDecodeInclusionBundle(f *testing.F) {
	f.Add([]byte("TLIP\x01"))
	f.Add(seedInclusionBundle())
	f.Fuzz(func(t *testing.T, in []byte) {
		b, err := DecodeInclusionBundle(in)
		if err != nil {
			return
		}
		out, err := b.MarshalBinary()
		if err != nil || string(out) != string(in) {
			t.Fatalf("non-canonical bundle")
		}
	})
}

func FuzzDecodeConsistencyBundle(f *testing.F) {
	f.Add([]byte("TLCS\x01"))
	f.Add(seedConsistencyBundle())
	f.Fuzz(func(t *testing.T, in []byte) {
		b, err := DecodeConsistencyBundle(in)
		if err != nil {
			return
		}
		out, err := b.MarshalBinary()
		if err != nil || string(out) != string(in) {
			t.Fatalf("non-canonical bundle")
		}
	})
}

func TestVerifyWithoutLockAccess(t *testing.T) {
	f := newFixture(t).build(2)
	lock := filepath.Join(f.dir, "LOCK")
	os.Remove(lock)
	os.Mkdir(lock, 0o755) // opening LOCK for writing now fails, like a read-only copy
	r := f.verify(nil)
	if !r.OK || r.Live || len(r.Warnings) == 0 {
		t.Fatalf("%s live=%v warnings=%v", r, r.Live, r.Warnings)
	}
}
