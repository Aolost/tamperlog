package storage

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Aolost/tamperlog/merkle"
	"github.com/Aolost/tamperlog/reason"
)

// SegmentDir is the name of the segments directory inside a log directory.
const SegmentDir = "segments"

// SegmentExt is the segment file extension.
const SegmentExt = ".seg"

// DefaultSegmentSize is the default maximum segment size.
const DefaultSegmentSize = 64 << 20

// SegmentName returns the file name of the segment whose first entry is seq.
func SegmentName(firstSeq uint64) string {
	return fmt.Sprintf("%020d%s", firstSeq, SegmentExt)
}

// ListSegments returns the segment file names in dir/segments in order.
func ListSegments(dir string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(dir, SegmentDir))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		n := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(n, SegmentExt) {
			continue
		}
		if _, err := strconv.ParseUint(strings.TrimSuffix(n, SegmentExt), 10, 64); err != nil {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// Record is one valid frame found by Scan.
type Record struct {
	Index   uint64 // position in the log (0-based), not the entry's claimed seq
	Segment string
	Offset  int64
	Entry   []byte // valid only during the callback
	Hash    merkle.Hash
}

// FrameError is a framing problem at a precise location.
type FrameError struct {
	Reason  reason.Code
	Index   uint64 // position of the record that failed
	Segment string
	Offset  int64
	Detail  string
}

func (e *FrameError) Error() string {
	return fmt.Sprintf("%s at position %d, segment %s offset %d: %s", e.Reason, e.Index, e.Segment, e.Offset, e.Detail)
}

// Torn describes an incomplete frame at the end of the last segment.
type Torn struct {
	Index   uint64
	Segment string
	Offset  int64 // offset of the incomplete frame = size to truncate to
	Bytes   int64 // number of trailing bytes that are not a complete frame
}

// SegmentInfo describes a scanned segment.
type SegmentInfo struct {
	Name       string
	FirstIndex uint64
	Size       int64 // valid size (excluding any torn tail)
}

// ScanResult summarizes a scan.
type ScanResult struct {
	Segments []SegmentInfo
	Records  uint64
	Torn     *Torn
}

// ErrStop can be returned by a Scan callback to stop early without error.
var ErrStop = errors.New("storage: stop scan")

// Scan reads every segment in order, calling fn for each valid frame. A torn
// tail in the last segment is reported in ScanResult.Torn, not as an error.
// Any other framing problem returns a *FrameError. Errors returned by fn are
// returned as is (ErrStop stops the scan and returns nil).
func Scan(dir string, fn func(Record) error) (ScanResult, error) {
	var res ScanResult
	names, err := ListSegments(dir)
	if err != nil {
		return res, err
	}
	var index uint64
	for si, name := range names {
		isLast := si == len(names)-1
		buf, err := os.ReadFile(filepath.Join(dir, SegmentDir, name))
		if err != nil {
			return res, err
		}
		info := SegmentInfo{Name: name, FirstIndex: index}
		off := 0
		for off < len(buf) {
			fr, st := ParseFrame(buf[off:])
			fail := func(code reason.Code, detail string) error {
				return &FrameError{Reason: code, Index: index, Segment: name, Offset: int64(off), Detail: detail}
			}
			switch st {
			case FrameOK:
				if fn != nil {
					err := fn(Record{Index: index, Segment: name, Offset: int64(off), Entry: fr.Entry, Hash: fr.Hash})
					if errors.Is(err, ErrStop) {
						info.Size = int64(off + fr.Size)
						res.Segments = append(res.Segments, info)
						res.Records = index + 1
						return res, nil
					}
					if err != nil {
						return res, err
					}
				}
				off += fr.Size
				index++
				continue
			case FrameIncomplete:
				if isLast && !validFrameAfter(buf, off+1) {
					res.Torn = &Torn{Index: index, Segment: name, Offset: int64(off), Bytes: int64(len(buf) - off)}
					break
				}
				if isLast {
					return res, fail(reason.RecordTruncated, "incomplete frame followed by valid data")
				}
				return res, fail(reason.RecordTruncated, "incomplete frame at end of non-final segment")
			case FrameBadLength:
				if isLast && allZero(buf[off:]) {
					res.Torn = &Torn{Index: index, Segment: name, Offset: int64(off), Bytes: int64(len(buf) - off)}
					break
				}
				return res, fail(reason.RecordLength, "length prefix out of range")
			case FrameBadCRC:
				return res, fail(reason.RecordCRC, "crc32c mismatch")
			}
			break // torn: stop scanning this (last) segment
		}
		if res.Torn == nil {
			info.Size = int64(off)
		} else {
			info.Size = res.Torn.Offset
		}
		res.Segments = append(res.Segments, info)
	}
	res.Records = index
	return res, nil
}

// TruncateTorn truncates the segment holding a torn tail and fsyncs it.
func TruncateTorn(dir string, t *Torn) error {
	f, err := os.OpenFile(filepath.Join(dir, SegmentDir, t.Segment), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(t.Offset); err != nil {
		return err
	}
	return f.Sync()
}

// ReadFrameAt reads one frame of known entry length from a segment.
func ReadFrameAt(r io.ReaderAt, off int64, entryLen int) (Frame, error) {
	buf := make([]byte, FrameSize(entryLen))
	if _, err := r.ReadAt(buf, off); err != nil {
		return Frame{}, err
	}
	fr, st := ParseFrame(buf)
	if st != FrameOK || fr.Size != len(buf) {
		return Frame{}, fmt.Errorf("storage: frame at offset %d changed on disk", off)
	}
	return fr, nil
}
