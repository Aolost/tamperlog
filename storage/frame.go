// Package storage implements tamperlog's on-disk segment format: framed
// records, segment scanning with torn-tail versus corruption classification,
// the segment writer, and the single-writer directory lock.
package storage

import (
	"encoding/binary"
	"hash/crc32"

	"github.com/Aolost/tamperlog/entry"
	"github.com/Aolost/tamperlog/merkle"
)

// HeaderSize is the frame header: length u32 + crc32c u32.
const HeaderSize = 8

// Overhead is the per-frame overhead: header plus the stored entry hash.
const Overhead = HeaderSize + merkle.HashSize

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// frameCRC is CRC-32C over length || entry bytes || entry hash.
func frameCRC(lenField []byte, entryBytes []byte, h []byte) uint32 {
	c := crc32.Update(0, castagnoli, lenField)
	c = crc32.Update(c, castagnoli, entryBytes)
	return crc32.Update(c, castagnoli, h)
}

// AppendFrame appends [length][crc32c][entry bytes][entry hash] to dst.
func AppendFrame(dst, entryBytes []byte, h merkle.Hash) []byte {
	var lf [4]byte
	binary.BigEndian.PutUint32(lf[:], uint32(len(entryBytes)))
	dst = append(dst, lf[:]...)
	dst = binary.BigEndian.AppendUint32(dst, frameCRC(lf[:], entryBytes, h[:]))
	dst = append(dst, entryBytes...)
	return append(dst, h[:]...)
}

// FrameSize returns the encoded size of a frame for an entry of n bytes.
func FrameSize(n int) int { return Overhead + n }

// Status is the outcome of parsing one frame.
type Status int

// Frame parse outcomes.
const (
	FrameOK Status = iota
	FrameIncomplete
	FrameBadLength
	FrameBadCRC
)

// Frame is a parsed frame. Entry aliases the input buffer.
type Frame struct {
	Entry []byte
	Hash  merkle.Hash
	Size  int // total bytes consumed
}

// ParseFrame parses the frame at the start of b.
func ParseFrame(b []byte) (Frame, Status) {
	if len(b) < HeaderSize {
		return Frame{}, FrameIncomplete
	}
	n := binary.BigEndian.Uint32(b[0:4])
	if n < entry.HeaderSize || n > entry.MaxEncodedSize {
		return Frame{}, FrameBadLength
	}
	size := HeaderSize + int(n) + merkle.HashSize
	if len(b) < size {
		return Frame{}, FrameIncomplete
	}
	eb := b[HeaderSize : HeaderSize+int(n)]
	hb := b[HeaderSize+int(n) : size]
	if frameCRC(b[0:4], eb, hb) != binary.BigEndian.Uint32(b[4:8]) {
		return Frame{}, FrameBadCRC
	}
	var f Frame
	f.Entry = eb
	copy(f.Hash[:], hb)
	f.Size = size
	return f, FrameOK
}

// FixCRC recomputes the CRC of a complete frame in place. It exists for the
// tamper simulation suite, which models an attacker who can recompute CRCs.
func FixCRC(frame []byte) {
	n := binary.BigEndian.Uint32(frame[0:4])
	end := HeaderSize + int(n)
	if end+merkle.HashSize > len(frame) {
		return
	}
	binary.BigEndian.PutUint32(frame[4:8], frameCRC(frame[0:4], frame[HeaderSize:end], frame[end:end+merkle.HashSize]))
}

// validFrameAfter reports whether any complete, CRC-valid frame starts at or
// after offset start in b. Used to tell a torn tail (nothing valid after it)
// from corruption that hides later records.
func validFrameAfter(b []byte, start int) bool {
	for p := start; p+Overhead+entry.HeaderSize <= len(b); p++ {
		if _, st := ParseFrame(b[p:]); st == FrameOK {
			return true
		}
	}
	return false
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
