package tamperlog

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Aolost/tamperlog/checkpoint"
	"github.com/Aolost/tamperlog/entry"
	"github.com/Aolost/tamperlog/merkle"
	"github.com/Aolost/tamperlog/reason"
	"github.com/Aolost/tamperlog/storage"
)

// Finding is one verification failure with its precise location.
type Finding struct {
	Reason  reason.Code `json:"reason"`
	Seq     int64       `json:"seq"`     // first bad sequence number, or -1
	Segment string      `json:"segment"` // segment file, or ""
	Offset  int64       `json:"offset"`  // byte offset in Segment, or -1
	File    string      `json:"file"`    // checkpoint file, "witness", or ""
	Detail  string      `json:"detail"`
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func num(n int64) string {
	if n < 0 {
		return "-"
	}
	return strconv.FormatInt(n, 10)
}

// String renders the machine-readable failure line.
func (f *Finding) String() string {
	s := fmt.Sprintf("FAIL reason=%s seq=%s segment=%s offset=%s", f.Reason, num(f.Seq), dash(f.Segment), num(f.Offset))
	if f.File != "" {
		s += " file=" + f.File
	}
	return s + " detail=" + strconv.Quote(f.Detail)
}

// Error makes a Finding usable as an error.
func (f *Finding) Error() string { return f.String() }

// CorruptionError is returned by Open when the log cannot be vouched for.
type CorruptionError struct{ Finding }

func (e *CorruptionError) Error() string { return "tamperlog: refusing to open: " + e.Finding.String() }

// Unwrap lets errors.As find the Finding.
func (e *CorruptionError) Unwrap() error { return &e.Finding }

// loc locates one record on disk.
type loc struct {
	seg uint32
	off int64
	n   uint32 // entry length
}

// scanned is the reconstructed state of a log after a full scan.
type scanned struct {
	tree   *merkle.Tree
	locs   []loc
	segs   []string
	res    storage.ScanResult
	head   merkle.Hash
	lastTS int64
}

// scanEntries reads every record and checks framing, decoding, stored hash,
// seq, chain and timestamps. A *Finding is returned for the first problem; an
// ordinary error for I/O problems. A torn tail is left in res.Torn.
func scanEntries(dir string, logID [32]byte) (*scanned, *Finding, error) {
	s := &scanned{tree: merkle.NewTree()}
	chain := entry.NewChain(logID)
	segIdx := map[string]uint32{}
	var finding *Finding
	res, err := storage.Scan(dir, func(r storage.Record) error {
		at := func(code reason.Code, seq uint64, detail string) error {
			finding = &Finding{Reason: code, Seq: int64(seq), Segment: r.Segment, Offset: r.Offset, Detail: detail}
			return storage.ErrStop
		}
		e, err := entry.Unmarshal(r.Entry)
		if err != nil {
			return at(reason.EntryDecode, r.Index, err.Error())
		}
		h := entry.Hash(r.Entry)
		if h != r.Hash {
			return at(reason.EntryHashMismatch, r.Index, "stored entry hash does not match entry bytes")
		}
		if err := chain.Add(&e, h); err != nil {
			var ce *entry.ChainError
			errors.As(err, &ce)
			switch ce.Reason {
			case entry.ReasonSeq:
				return at(classifySeq(dir, r.Index, e.Seq), r.Index, fmt.Sprintf("expected seq %d, entry claims seq %d", r.Index, e.Seq))
			case entry.ReasonPrevHash:
				return at(reason.ChainBreak, r.Index, "prev_hash does not match the previous entry hash")
			default:
				return at(reason.TimestampRegression, r.Index, fmt.Sprintf("timestamp %d is before previous %d", e.Timestamp, chain.LastTimestamp()))
			}
		}
		si, ok := segIdx[r.Segment]
		if !ok {
			si = uint32(len(s.segs))
			segIdx[r.Segment] = si
			s.segs = append(s.segs, r.Segment)
		}
		s.locs = append(s.locs, loc{seg: si, off: r.Offset, n: uint32(len(r.Entry))})
		s.tree.AppendLeafHash(h)
		return nil
	})
	if finding != nil {
		return nil, finding, nil
	}
	if err != nil {
		var fe *storage.FrameError
		if errors.As(err, &fe) {
			return nil, &Finding{Reason: fe.Reason, Seq: int64(fe.Index), Segment: fe.Segment, Offset: fe.Offset, Detail: fe.Detail}, nil
		}
		return nil, nil, err
	}
	// Make sure every segment (including empty ones) has a slot.
	for _, si := range res.Segments {
		if _, ok := segIdx[si.Name]; !ok {
			segIdx[si.Name] = uint32(len(s.segs))
			s.segs = append(s.segs, si.Name)
		}
	}
	s.res = res
	s.head = chain.Head()
	s.lastTS = chain.LastTimestamp()
	return s, nil, nil
}

// classifySeq decides between a gap, a duplicate and a reordering when the
// record at position idx claims seq claimed. It rescans the log for the seqs
// claimed by later records.
func classifySeq(dir string, idx, claimed uint64) reason.Code {
	if claimed < idx {
		return reason.SeqDuplicate
	}
	found := false
	storage.Scan(dir, func(r storage.Record) error {
		if r.Index > idx && len(r.Entry) >= 9 && binary.BigEndian.Uint64(r.Entry[1:9]) == idx {
			found = true
			return storage.ErrStop
		}
		return nil
	})
	if found {
		return reason.SeqOrder
	}
	return reason.SeqGap
}

// cpFile is a checkpoint file read from disk.
type cpFile struct {
	name string
	cp   *checkpoint.Checkpoint
	err  error
}

// readCheckpoints reads all checkpoint files, sorted by tree size (files
// that fail to decode first, so they are reported).
func readCheckpoints(dir string) ([]cpFile, error) {
	ents, err := os.ReadDir(filepath.Join(dir, CheckpointDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []cpFile
	for _, e := range ents {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), checkpointExt) {
			continue
		}
		cp, err := checkpoint.ReadFile(filepath.Join(dir, CheckpointDir, e.Name()))
		out = append(out, cpFile{name: e.Name(), cp: cp, err: err})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if (a.err != nil) != (b.err != nil) {
			return a.err != nil
		}
		if a.err != nil {
			return a.name < b.name
		}
		if a.cp.TreeSize != b.cp.TreeSize {
			return a.cp.TreeSize < b.cp.TreeSize
		}
		return a.name < b.name
	})
	return out, nil
}

func checkpointName(size uint64) string { return fmt.Sprintf("%020d%s", size, checkpointExt) }
