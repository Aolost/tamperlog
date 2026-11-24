package tamperlog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Aolost/tamperlog/entry"
	"github.com/Aolost/tamperlog/reason"
	"github.com/Aolost/tamperlog/storage"
)

var errCrash = errors.New("simulated crash")

// cutFile passes writes through until the armed write, of which it persists
// only the first `cut` bytes before failing, simulating a crash mid-write.
type cutFile struct {
	storage.WriteFile
	armed *bool
	cut   int
}

func (c *cutFile) Write(p []byte) (int, error) {
	if !*c.armed {
		return c.WriteFile.Write(p)
	}
	*c.armed = false
	n := c.cut
	if n >= len(p) {
		return c.WriteFile.Write(p)
	}
	if n > 0 {
		if _, err := c.WriteFile.Write(p[:n]); err != nil {
			return 0, err
		}
	}
	return n, errCrash
}

func entriesOf(t *testing.T, l *Log) [][]byte {
	t.Helper()
	var out [][]byte
	for i := uint64(0); i < l.Size(); i++ {
		b, err := l.EntryBytes(i)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

// TestCrashAtEveryByteOffset cuts the next record at every offset 0..len.
// After reopening, the log holds either exactly the previous records or
// exactly the previous records plus the new one. Never a half record, never
// loss of earlier data.
func TestCrashAtEveryByteOffset(t *testing.T) {
	payload := []byte("crash-test-payload")
	frameLen := storage.FrameSize(entry.HeaderSize + len(payload))
	for cut := 0; cut <= frameLen; cut++ {
		f := newFixture(t).build(3)
		l := f.open(f.opts())
		before := entriesOf(t, l)
		l.Close()

		armed := false
		o := f.opts()
		o.WrapFile = func(w storage.WriteFile) storage.WriteFile { return &cutFile{WriteFile: w, armed: &armed, cut: cut} }
		l = f.open(o)
		armed = true
		_, err := l.Append(payload)
		if cut < frameLen {
			if !errors.Is(err, errCrash) {
				t.Fatalf("cut=%d: want crash error, got %v", cut, err)
			}
			if _, err := l.Append([]byte("after")); !errors.Is(err, ErrPoisoned) {
				t.Fatalf("cut=%d: writer not poisoned: %v", cut, err)
			}
			if _, err := l.Checkpoint(); !errors.Is(err, ErrPoisoned) {
				t.Fatal("checkpoint on poisoned log")
			}
		} else if err != nil {
			t.Fatalf("cut=%d: %v", cut, err)
		}
		l.Close()

		var logbuf bytes.Buffer
		o = f.opts()
		o.Logger = slog.New(slog.NewTextHandler(&logbuf, nil))
		l, err = Open(f.dir, o)
		if err != nil {
			t.Fatalf("cut=%d: reopen: %v", cut, err)
		}
		after := entriesOf(t, l)
		want := len(before)
		if cut == frameLen {
			want++
		}
		if len(after) != want {
			t.Fatalf("cut=%d: size %d, want %d", cut, len(after), want)
		}
		for i := range before {
			if !bytes.Equal(before[i], after[i]) {
				t.Fatalf("cut=%d: entry %d changed", cut, i)
			}
		}
		if cut > 0 && cut < frameLen && !strings.Contains(logbuf.String(), "torn") {
			t.Fatalf("cut=%d: no torn-tail warning logged: %q", cut, logbuf.String())
		}
		if _, err := l.Append([]byte("next")); err != nil {
			t.Fatalf("cut=%d: append after recovery: %v", cut, err)
		}
		l.Close()
		if r := f.verify(nil); !r.OK {
			t.Fatalf("cut=%d: verify after recovery: %s", cut, r)
		}
	}
}

func openErr(t *testing.T, f *fixture) *CorruptionError {
	t.Helper()
	_, err := Open(f.dir, f.opts())
	var ce *CorruptionError
	if !errors.As(err, &ce) {
		t.Fatalf("want CorruptionError, got %v", err)
	}
	if !strings.Contains(ce.Error(), "refusing to open") || !strings.Contains(ce.Error(), "offset=") {
		t.Fatalf("error text: %s", ce.Error())
	}
	var fd *Finding
	if !errors.As(err, &fd) {
		t.Fatal("unwrap to Finding")
	}
	return ce
}

func TestOpenRefusesMidFileCorruption(t *testing.T) {
	t.Run("crc_mid_file", func(t *testing.T) {
		f := newFixture(t).build(5)
		fr := flip(f, 2, fields[7], false, false)
		ce := openErr(t, f)
		if ce.Reason != reason.RecordCRC || ce.Offset != int64(fr.off) || ce.Seq != 2 {
			t.Fatal(ce)
		}
	})
	t.Run("crc_complete_last_frame", func(t *testing.T) {
		// A fully present final frame with a bad CRC is not a torn write.
		f := newFixture(t).build(5)
		flip(f, 4, fields[7], false, false)
		if ce := openErr(t, f); ce.Reason != reason.RecordCRC {
			t.Fatal(ce)
		}
	})
	t.Run("incomplete_then_valid", func(t *testing.T) {
		f := newFixture(t).build(5)
		rewriteFrames(f, func(b []byte, fr []frameRef) []byte {
			out := append([]byte{}, b[:fr[4].off]...)
			var hdr [8]byte
			binary.BigEndian.PutUint32(hdr[:], 5000) // claims more than remains
			out = append(out, hdr[:]...)
			return append(out, cut(b, fr[4])...) // a valid frame hides behind it
		})
		if ce := openErr(t, f); ce.Reason != reason.RecordTruncated || ce.Seq != 4 {
			t.Fatal(ce)
		}
	})
	t.Run("bad_length_mid_file", func(t *testing.T) {
		f := newFixture(t).build(5)
		rewriteFrames(f, func(b []byte, fr []frameRef) []byte {
			binary.BigEndian.PutUint32(b[fr[1].off:], 3) // below minimum entry size
			return b
		})
		if ce := openErr(t, f); ce.Reason != reason.RecordLength || ce.Seq != 1 {
			t.Fatal(ce)
		}
	})
	t.Run("chain_break", func(t *testing.T) {
		f := newFixture(t).build(5)
		flip(f, 1, fields[7], true, true)
		if ce := openErr(t, f); ce.Reason != reason.ChainBreak || ce.Seq != 2 {
			t.Fatal(ce)
		}
	})
	t.Run("checkpoint_ahead_of_data", func(t *testing.T) {
		f := newFixture(t).build(5)
		rewriteFrames(f, func(b []byte, fr []frameRef) []byte { return b[:fr[4].off] })
		if ce := openErr(t, f); ce.Reason != reason.LogTruncated || ce.Seq != 4 {
			t.Fatal(ce)
		}
	})
	t.Run("checkpoint_root_mismatch", func(t *testing.T) {
		f := newFixture(t).build(5)
		flip(f, 4, fields[7], true, true)
		if ce := openErr(t, f); ce.Reason != reason.CheckpointRootMismatch {
			t.Fatal(ce)
		}
	})
	t.Run("checkpoint_garbage", func(t *testing.T) {
		f := newFixture(t).build(2)
		os.WriteFile(filepath.Join(f.dir, CheckpointDir, checkpointName(2)), []byte("x"), 0o644)
		if ce := openErr(t, f); ce.Reason != reason.CheckpointDecode {
			t.Fatal(ce)
		}
	})
}

func TestTornTailVariantsRecovered(t *testing.T) {
	for name, tail := range map[string][]byte{
		"partial_header": {0x00, 0x00},
		"zero_fill":      make([]byte, 100),
		"partial_body":   append([]byte{0, 0, 0, 80, 1, 2, 3, 4}, make([]byte, 20)...),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t).build(3)
			fr := f.frames()
			b := f.readSeg(fr[0].seg)
			f.writeSeg(fr[0].seg, append(append([]byte{}, b...), tail...))
			l := f.open(f.opts())
			if l.Size() != 3 {
				t.Fatal("size")
			}
			l.Close()
			mustEqual(t, f.readSeg(fr[0].seg), b)
		})
	}
}

func TestLeftoverTempCheckpointRemoved(t *testing.T) {
	f := newFixture(t).build(2)
	tmp := filepath.Join(f.dir, CheckpointDir, checkpointName(3)+".tmp")
	os.WriteFile(tmp, []byte("half"), 0o644)
	l := f.open(f.opts())
	l.Close()
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("tmp not removed")
	}
	if r := f.verify(nil); !r.OK {
		t.Fatal(r)
	}
}

func TestSegmentRolloverAndReopen(t *testing.T) {
	f := newFixture(t)
	o := f.opts()
	o.SegmentSize = 300
	o.Sync = SyncBatch
	o.BatchSize = 3
	l := f.open(o)
	for i := 0; i < 50; i++ {
		if _, err := l.Append(bytes.Repeat([]byte{byte(i)}, i)); err != nil {
			t.Fatal(err)
		}
	}
	root := l.Root()
	l.Close()
	segs, _ := storage.ListSegments(f.dir)
	if len(segs) < 5 {
		t.Fatalf("segments: %d", len(segs))
	}
	l = f.open(o)
	if l.Root() != root || l.Size() != 50 {
		t.Fatal("reopen state")
	}
	for i := uint64(0); i < 50; i++ {
		e, err := l.Entry(i)
		if err != nil || e.Seq != i || len(e.Payload) != int(i) {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	// An oversized frame gets its own segment.
	if _, err := l.Append(make([]byte, 1000)); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if r := f.verify(nil); !r.OK {
		t.Fatal(r)
	}
}

func TestEmptyLastSegmentAfterCrash(t *testing.T) {
	f := newFixture(t).build(2)
	// Crash right after a roll-over created a new, empty segment.
	os.WriteFile(f.segPath(storage.SegmentName(2)), nil, 0o644)
	l := f.open(f.opts())
	if _, err := l.Append([]byte("x")); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if r := f.verify(nil); !r.OK || r.Size != 3 {
		t.Fatal(r)
	}
}

// failSync makes every fsync fail, as on a dying disk.
type failSync struct{ storage.WriteFile }

func (failSync) Sync() error { return errors.New("EIO") }

func TestFsyncFailurePoisons(t *testing.T) {
	f := newFixture(t).build(1)
	o := f.opts()
	o.Sync = SyncEvery
	o.WrapFile = func(w storage.WriteFile) storage.WriteFile { return failSync{w} }
	l := f.open(o)
	if _, err := l.Append([]byte("x")); err == nil || !strings.Contains(err.Error(), "fsync") {
		t.Fatalf("want fsync error, got %v", err)
	}
	if _, err := l.Append([]byte("y")); !errors.Is(err, ErrPoisoned) {
		t.Fatal("not poisoned")
	}
	if err := l.Sync(); !errors.Is(err, ErrPoisoned) {
		t.Fatal("sync on poisoned")
	}
	l.Close()

	o.Sync = SyncNone
	l = f.open(o)
	if err := l.Sync(); err == nil {
		t.Fatal("explicit Sync must surface the error even under SyncNone")
	}
	l.Close()
	l = f.open(o)
	if _, err := l.Checkpoint(); err == nil {
		t.Fatal("checkpoint must fsync data first")
	}
	l.Close()
	if (&Finding{Reason: reason.ChainBreak, Seq: 1, Offset: 2}).Error() == "" {
		t.Fatal()
	}
}

func TestReadOnlyOpen(t *testing.T) {
	f := newFixture(t).build(3)
	w := f.open(f.opts()) // a live writer holds the lock
	defer w.Close()
	fr := f.frames()
	b := f.readSeg(fr[0].seg)
	f.writeSeg(fr[0].seg, append(append([]byte{}, b...), 0, 0, 0)) // append in progress
	r, err := Open(f.dir, Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Size() != 3 || r.LatestCheckpoint() == nil {
		t.Fatal("read-only state")
	}
	if _, err := r.Append(nil); !errors.Is(err, ErrReadOnly) {
		t.Fatal("append on read-only")
	}
	mustEqual(t, f.readSeg(fr[0].seg)[:len(b)+3], append(append([]byte{}, b...), 0, 0, 0)) // untouched
}
