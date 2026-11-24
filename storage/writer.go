package storage

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/Aolost/tamperlog/checkpoint"
)

// WriteFile is the subset of *os.File the writer needs. Tests wrap it to
// inject crashes at arbitrary byte offsets.
type WriteFile interface {
	Write(p []byte) (int, error)
	Sync() error
	Close() error
}

// WriterOptions configures a segment writer.
type WriterOptions struct {
	// SegmentSize is the size at which a new segment is started. A frame is
	// never split; a single frame larger than SegmentSize gets its own segment.
	SegmentSize int64
	// WrapFile, if set, wraps every segment file opened for writing.
	WrapFile func(WriteFile) WriteFile
}

// Writer appends frames to the current segment, rolling over as needed. It
// is not safe for concurrent use; the caller serializes appends.
type Writer struct {
	dir      string
	opts     WriterOptions
	f        WriteFile
	name     string
	size     int64
	next     uint64 // index of the next record
	onNewSeg func(name string)
}

// ErrClosed is returned after Close.
var ErrClosed = errors.New("storage: writer closed")

// NewWriter continues the log after recovery. last is the final segment
// (zero value if there are none), next is the number of records in the log.
// onNewSeg is called (under the caller's lock) whenever a segment is created.
func NewWriter(dir string, last SegmentInfo, next uint64, opts WriterOptions, onNewSeg func(string)) (*Writer, error) {
	if opts.SegmentSize <= 0 {
		opts.SegmentSize = DefaultSegmentSize
	}
	if err := os.MkdirAll(filepath.Join(dir, SegmentDir), 0o755); err != nil {
		return nil, err
	}
	w := &Writer{dir: dir, opts: opts, next: next, onNewSeg: onNewSeg}
	if last.Name != "" {
		f, err := os.OpenFile(filepath.Join(dir, SegmentDir, last.Name), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return nil, err
		}
		w.f, w.name, w.size = w.wrap(f), last.Name, last.Size
	}
	return w, nil
}

func (w *Writer) wrap(f *os.File) WriteFile {
	if w.opts.WrapFile != nil {
		return w.opts.WrapFile(f)
	}
	return f
}

// Append writes one frame and returns the segment and offset it was written at.
// It does not fsync.
func (w *Writer) Append(frame []byte) (string, int64, error) {
	if w.dir == "" {
		return "", 0, ErrClosed
	}
	if w.f == nil || (w.size > 0 && w.size+int64(len(frame)) > w.opts.SegmentSize) {
		if err := w.roll(); err != nil {
			return "", 0, err
		}
	}
	off := w.size
	n, err := w.f.Write(frame)
	w.size += int64(n)
	if err != nil {
		return "", 0, err
	}
	w.next++
	return w.name, off, nil
}

func (w *Writer) roll() error {
	if w.f != nil {
		if err := w.f.Sync(); err != nil {
			return err
		}
		if err := w.f.Close(); err != nil {
			return err
		}
		w.f = nil
	}
	name := SegmentName(w.next)
	f, err := os.OpenFile(filepath.Join(w.dir, SegmentDir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if err := checkpoint.SyncDir(filepath.Join(w.dir, SegmentDir)); err != nil {
		f.Close()
		return err
	}
	w.f, w.name, w.size = w.wrap(f), name, 0
	if w.onNewSeg != nil {
		w.onNewSeg(name)
	}
	return nil
}

// Sync fsyncs the current segment.
func (w *Writer) Sync() error {
	if w.f == nil {
		return nil
	}
	return w.f.Sync()
}

// Close syncs and closes the current segment.
func (w *Writer) Close() error {
	if w.dir == "" {
		return nil
	}
	w.dir = ""
	if w.f == nil {
		return nil
	}
	err := w.f.Sync()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	return err
}
