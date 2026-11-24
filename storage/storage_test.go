package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Aolost/tamperlog/entry"
	"github.com/Aolost/tamperlog/reason"
)

func sampleFrame(payload string) []byte {
	e := entry.Entry{Seq: 0, Timestamp: 1, Payload: []byte(payload)}
	eb := e.AppendBinary(nil)
	return AppendFrame(nil, eb, entry.Hash(eb))
}

func TestParseFrame(t *testing.T) {
	fr := sampleFrame("hello")
	got, st := ParseFrame(fr)
	if st != FrameOK || got.Size != len(fr) || got.Size != FrameSize(len(got.Entry)) {
		t.Fatal("ok frame")
	}
	for i := 0; i < len(fr); i++ {
		if _, st := ParseFrame(fr[:i]); st != FrameIncomplete {
			t.Fatalf("prefix %d: %v", i, st)
		}
	}
	bad := append([]byte(nil), fr...)
	bad[len(bad)-1] ^= 1
	if _, st := ParseFrame(bad); st != FrameBadCRC {
		t.Fatal("crc")
	}
	FixCRC(bad)
	if _, st := ParseFrame(bad); st != FrameOK {
		t.Fatal("FixCRC")
	}
	FixCRC(bad[:10]) // must not panic on a short frame
	if _, st := ParseFrame(make([]byte, 64)); st != FrameBadLength {
		t.Fatal("zero length")
	}
	if !validFrameAfter(append([]byte{1, 2, 3}, fr...), 1) || validFrameAfter(fr, 1) {
		t.Fatal("validFrameAfter")
	}
}

func writeSegs(t *testing.T, segs map[string][]byte) string {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, SegmentDir), 0o755)
	for n, b := range segs {
		os.WriteFile(filepath.Join(dir, SegmentDir, n), b, 0o644)
	}
	return dir
}

func TestScanClassification(t *testing.T) {
	fr := sampleFrame("abc")
	two := append(append([]byte{}, fr...), fr...)

	dir := writeSegs(t, map[string][]byte{SegmentName(0): two, SegmentName(2): append(append([]byte{}, fr...), fr[:5]...), "junk.txt": {1}, "x.seg": {1}})
	res, err := Scan(dir, nil)
	if err != nil || res.Records != 3 || res.Torn == nil || res.Torn.Offset != int64(len(fr)) || res.Torn.Index != 3 || len(res.Segments) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	if err := TruncateTorn(dir, res.Torn); err != nil {
		t.Fatal(err)
	}
	if res, _ := Scan(dir, nil); res.Torn != nil || res.Records != 3 {
		t.Fatal("after truncate")
	}

	// Incomplete frame in a non-final segment is corruption.
	dir = writeSegs(t, map[string][]byte{SegmentName(0): fr[:20], SegmentName(1): fr})
	_, err = Scan(dir, nil)
	var fe *FrameError
	if !errors.As(err, &fe) || fe.Reason != reason.RecordTruncated || fe.Offset != 0 || !strings.Contains(fe.Error(), "RECORD_TRUNCATED") {
		t.Fatal(err)
	}

	// Bad length in the middle.
	b := append([]byte{}, two...)
	b[len(fr)+3] = 1
	dir = writeSegs(t, map[string][]byte{SegmentName(0): b})
	if _, err := Scan(dir, nil); !errors.As(err, &fe) || fe.Reason != reason.RecordLength || fe.Index != 1 {
		t.Fatal(err)
	}

	// Callback errors propagate; ErrStop stops cleanly.
	dir = writeSegs(t, map[string][]byte{SegmentName(0): two})
	boom := errors.New("boom")
	if _, err := Scan(dir, func(Record) error { return boom }); err != boom {
		t.Fatal(err)
	}
	if res, err := Scan(dir, func(Record) error { return ErrStop }); err != nil || res.Records != 1 {
		t.Fatal(err)
	}
	if _, err := Scan(t.TempDir(), nil); err == nil {
		t.Fatal("missing segment dir")
	}
	if err := TruncateTorn(t.TempDir(), &Torn{Segment: "nope"}); err == nil {
		t.Fatal("truncate missing")
	}
}

func TestReadFrameAt(t *testing.T) {
	fr := sampleFrame("abc")
	f, err := ReadFrameAt(bytes.NewReader(fr), 0, len(fr)-Overhead)
	if err != nil || f.Size != len(fr) {
		t.Fatal(err)
	}
	if _, err := ReadFrameAt(bytes.NewReader(fr), 1, len(fr)-Overhead); err == nil {
		t.Fatal("misaligned")
	}
	bad := append([]byte(nil), fr...)
	bad[20] ^= 1
	if _, err := ReadFrameAt(bytes.NewReader(bad), 0, len(fr)-Overhead); err == nil {
		t.Fatal("changed on disk")
	}
}

func TestWriterAndLock(t *testing.T) {
	dir := t.TempDir()
	var created []string
	w, err := NewWriter(dir, SegmentInfo{}, 0, WriterOptions{SegmentSize: 100}, func(n string) { created = append(created, n) })
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Sync(); err != nil {
		t.Fatal("sync with no file")
	}
	fr := sampleFrame("abc")
	for i := 0; i < 4; i++ {
		if _, _, err := w.Append(fr); err != nil {
			t.Fatal(err)
		}
	}
	if len(created) != 4 || w.Close() != nil || w.Close() != nil {
		t.Fatalf("segments %v", created)
	}
	if _, _, err := w.Append(fr); !errors.Is(err, ErrClosed) {
		t.Fatal("append after close")
	}
	w2, _ := NewWriter(t.TempDir(), SegmentInfo{}, 0, WriterOptions{}, nil)
	if w2.Close() != nil {
		t.Fatal("close empty writer")
	}
	if _, err := NewWriter(dir, SegmentInfo{Name: "missing.seg"}, 0, WriterOptions{}, nil); err == nil {
		t.Fatal("missing last segment")
	}
	// Name collision: roll-over refuses to clobber an existing segment.
	w3, _ := NewWriter(dir, SegmentInfo{}, 0, WriterOptions{}, nil)
	if _, _, err := w3.Append(fr); err == nil {
		t.Fatal("clobbered existing segment")
	}

	l1, err := LockExclusive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockExclusive(dir); !errors.Is(err, ErrLocked) {
		t.Fatal("double exclusive")
	}
	if _, err := LockShared(dir); !errors.Is(err, ErrLocked) {
		t.Fatal("shared while exclusive")
	}
	l1.Release()
	s1, err := LockShared(dir)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := LockShared(dir)
	if err != nil {
		t.Fatal("two readers")
	}
	s1.Release()
	s2.Release()
	var nilLock *Lock
	if nilLock.Release() != nil {
		t.Fatal("nil release")
	}
	if _, err := LockExclusive(filepath.Join(dir, "nope", "deeper")); err == nil {
		t.Fatal("lock in missing dir")
	}
}

func FuzzParseFrame(f *testing.F) {
	f.Add(sampleFrame("seed"))
	f.Add([]byte{0, 0, 0, 53, 0, 0, 0, 0})
	f.Add(make([]byte, 100))
	f.Fuzz(func(t *testing.T, in []byte) {
		fr, st := ParseFrame(in)
		if st != FrameOK {
			return
		}
		if fr.Size > len(in) {
			t.Fatal("size beyond input")
		}
		re := AppendFrame(nil, fr.Entry, fr.Hash)
		if !bytes.Equal(re, in[:fr.Size]) {
			t.Fatal("re-encode differs")
		}
		_ = validFrameAfter(in, 1)
	})
}
