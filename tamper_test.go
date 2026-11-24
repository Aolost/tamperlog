package tamperlog

// Tamper simulation matrix (TESTPLAN.md §1). Every case must fail with the
// expected reason code and location. None may be silently accepted, except the
// two documented limits, which are asserted explicitly so a change in
// behaviour is noticed.

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Aolost/tamperlog/checkpoint"
	"github.com/Aolost/tamperlog/reason"
	"github.com/Aolost/tamperlog/storage"
)

const nEntries = 8

func expect(t *testing.T, r *Report, code reason.Code, seq int64) {
	t.Helper()
	if r.OK {
		t.Fatalf("tamper accepted (want %s seq=%d): %s", code, seq, r)
	}
	if r.Failure.Reason != code {
		t.Fatalf("reason = %s, want %s (%s)", r.Failure.Reason, code, r.Failure)
	}
	if seq != -2 && r.Failure.Seq != seq {
		t.Fatalf("seq = %d, want %d (%s)", r.Failure.Seq, seq, r.Failure)
	}
}

func TestPristineVerifies(t *testing.T) {
	f := newFixture(t).build(nEntries)
	r := f.verify(f.checkpointAt(nEntries))
	if !r.OK || r.Size != nEntries || r.LatestCheckpoint != nEntries || r.UnsignedTail != 0 || !r.WitnessChecked {
		t.Fatalf("pristine log failed: %s %+v", r, r)
	}
	if r.String() == "" || r.Checkpoints != nEntries {
		t.Fatal("report")
	}
}

type field struct {
	name string
	off  func(fr frameRef) int
}

var fields = []field{
	{"length", func(frameRef) int { return offLen + 3 }},
	{"crc", func(frameRef) int { return offCRC }},
	{"version", func(frameRef) int { return offVersion }},
	{"seq", func(frameRef) int { return offSeq + 7 }},
	{"timestamp", func(frameRef) int { return offTS + 7 }},
	{"prev_hash", func(frameRef) int { return offPrev + 5 }},
	{"payload_len", func(frameRef) int { return offPLen + 3 }},
	{"payload", func(frameRef) int { return offPayload + 2 }},
	{"stored_hash", func(fr frameRef) int { return storage.HeaderSize + fr.entryLen + 4 }},
}

// flip flips bit 0 of the byte at field offset in frame idx, then applies the
// attacker's fixups.
func flip(f *fixture, idx int, fl field, fixCRC, fixHashToo bool) frameRef {
	fr := f.frames()[idx]
	b := f.readSeg(fr.seg)
	frame := b[fr.off : fr.off+fr.size]
	frame[fl.off(fr)] ^= 0x01
	if fixHashToo {
		fixHash(frame)
	}
	if fixCRC {
		storage.FixCRC(frame)
	}
	f.writeSeg(fr.seg, b)
	return fr
}

// Raw bit flips: the CRC catches every one, at the right offset.
func TestTamperRawBitFlip(t *testing.T) {
	const idx = 3
	for _, fl := range fields {
		t.Run(fl.name, func(t *testing.T) {
			f := newFixture(t).build(nEntries)
			fr := flip(f, idx, fl, false, false)
			r := f.verify(nil)
			want := reason.RecordCRC
			if fl.name == "length" {
				// The length now claims one more byte: the frame is still
				// "complete" but its CRC (which covers the length) fails.
				want = reason.RecordCRC
			}
			expect(t, r, want, idx)
			if r.Failure.Offset != int64(fr.off) || r.Failure.Segment != fr.seg {
				t.Fatalf("location %s@%d, want %s@%d", r.Failure.Segment, r.Failure.Offset, fr.seg, fr.off)
			}
		})
	}
}

// Attacker recomputes the CRC but not the stored entry hash.
func TestTamperCRCFixed(t *testing.T) {
	const idx = 3
	want := map[string]reason.Code{
		"version":     reason.EntryDecode,
		"payload_len": reason.EntryDecode,
		"seq":         reason.EntryHashMismatch,
		"timestamp":   reason.EntryHashMismatch,
		"prev_hash":   reason.EntryHashMismatch,
		"payload":     reason.EntryHashMismatch,
		"stored_hash": reason.EntryHashMismatch,
	}
	for _, fl := range fields {
		code, ok := want[fl.name]
		if !ok {
			continue
		}
		t.Run(fl.name, func(t *testing.T) {
			f := newFixture(t).build(nEntries)
			fr := flip(f, idx, fl, true, false)
			r := f.verify(nil)
			expect(t, r, code, idx)
			if r.Failure.Offset != int64(fr.off) {
				t.Fatalf("offset %d want %d", r.Failure.Offset, fr.off)
			}
		})
	}
}

// Attacker recomputes the stored hash and the CRC.
func TestTamperFullyFixed(t *testing.T) {
	cases := []struct {
		field string
		idx   int
		code  reason.Code
		seq   int64
	}{
		{"seq", 4, reason.SeqGap, 4},                                           // 4 -> 5: seq 4 is missing
		{"seq", 5, reason.SeqDuplicate, 5},                                     // 5 -> 4: duplicate of 4
		{"prev_hash", 3, reason.ChainBreak, 3},                                 // link itself is wrong
		{"timestamp", 3, reason.ChainBreak, 4},                                 // +1ns: next link breaks
		{"payload", 3, reason.ChainBreak, 4},                                   // next link breaks
		{"payload", nEntries - 1, reason.CheckpointRootMismatch, nEntries - 1}, // no next link: signed root catches it
		{"version", 3, reason.EntryDecode, 3},
	}
	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			f := newFixture(t).build(nEntries)
			var fl field
			for _, x := range fields {
				if x.name == c.field {
					fl = x
				}
			}
			flip(f, c.idx, fl, true, true)
			expect(t, f.verify(nil), c.code, c.seq)
		})
	}
}

// Attacker edits an entry and recomputes the entire chain after it: only the
// signed checkpoints catch it, and they bracket the edit precisely.
func TestTamperRewriteChain(t *testing.T) {
	f := newFixture(t).build(nEntries)
	flip(f, 2, fields[7], true, true) // payload of entry 2
	f.rechain(2)
	expect(t, f.verify(nil), reason.CheckpointRootMismatch, 2)

	// Without local checkpoints the rewrite is only caught by a witness.
	w := f.checkpointAt(nEntries)
	os.RemoveAll(filepath.Join(f.dir, CheckpointDir))
	if r := f.verify(nil); !r.OK {
		t.Fatalf("expected chain to be internally consistent: %s", r)
	}
	expect(t, f.verify(w), reason.WitnessRootMismatch, 0)
}

func rewriteFrames(f *fixture, edit func(b []byte, fr []frameRef) []byte) {
	fr := f.frames()
	b := f.readSeg(fr[0].seg)
	f.writeSeg(fr[0].seg, edit(b, fr))
}

func cut(b []byte, fr frameRef) []byte { return b[fr.off : fr.off+fr.size] }

func TestTamperDeleteMiddle(t *testing.T) {
	f := newFixture(t).build(nEntries)
	rewriteFrames(f, func(b []byte, fr []frameRef) []byte {
		return append(append([]byte{}, b[:fr[3].off]...), b[fr[4].off:]...)
	})
	r := f.verify(nil)
	expect(t, r, reason.SeqGap, 3)
	if r.Failure.Offset != int64(f.frames()[3].off) {
		t.Fatal("offset")
	}
}

func TestTamperDeleteLastWithLocalCheckpoint(t *testing.T) {
	f := newFixture(t).build(nEntries)
	rewriteFrames(f, func(b []byte, fr []frameRef) []byte { return b[:fr[nEntries-1].off] })
	expect(t, f.verify(nil), reason.LogTruncated, nEntries-1)
}

func TestTamperDeleteLastWithWitness(t *testing.T) {
	f := newFixture(t).build(nEntries)
	w := f.checkpointAt(nEntries)
	rewriteFrames(f, func(b []byte, fr []frameRef) []byte { return b[:fr[nEntries-1].off] })
	// The attacker also removes the newest local checkpoint.
	os.Remove(filepath.Join(f.dir, CheckpointDir, checkpointName(nEntries)))
	expect(t, f.verify(w), reason.WitnessRollback, nEntries-1)

	// Documented limit: without the witness this is a valid shorter log.
	if r := f.verify(nil); !r.OK || r.Size != nEntries-1 {
		t.Fatalf("documented limit changed: %s", r)
	}
}

func TestTamperSwap(t *testing.T) {
	f := newFixture(t).build(nEntries)
	rewriteFrames(f, func(b []byte, fr []frameRef) []byte {
		out := append([]byte{}, b[:fr[2].off]...)
		out = append(out, cut(b, fr[3])...)
		out = append(out, cut(b, fr[2])...)
		return append(out, b[fr[4].off:]...)
	})
	expect(t, f.verify(nil), reason.SeqOrder, 2)
}

func TestTamperDuplicate(t *testing.T) {
	f := newFixture(t).build(nEntries)
	rewriteFrames(f, func(b []byte, fr []frameRef) []byte {
		out := append([]byte{}, b[:fr[4].off]...)
		out = append(out, cut(b, fr[3])...)
		return append(out, b[fr[4].off:]...)
	})
	expect(t, f.verify(nil), reason.SeqDuplicate, 4)
}

func TestTamperRollbackToValidPrefix(t *testing.T) {
	f := newFixture(t).build(5)
	backup := filepath.Join(t.TempDir(), "backup")
	copyDir(t, f.dir, backup)
	l := f.open(f.opts())
	for i := 0; i < 3; i++ {
		l.Append([]byte("later"))
	}
	l.Close()
	w := f.checkpointAt(8) // a witness received this
	os.RemoveAll(f.dir)
	copyDir(t, backup, f.dir)

	// Documented limit: the older copy is internally valid.
	if r := f.verify(nil); !r.OK || r.Size != 5 {
		t.Fatalf("documented limit changed: %s", r)
	}
	expect(t, f.verify(w), reason.WitnessRollback, 5)
}

func spliceFrom(t *testing.T, f *fixture, idx int) {
	other := newFixture(t)
	other.priv, other.pub = f.priv, f.pub // same key, different log
	other.build(nEntries)
	ofr := other.frames()
	ob := other.readSeg(ofr[0].seg)
	rewriteFrames(f, func(b []byte, fr []frameRef) []byte {
		out := append([]byte{}, b[:fr[idx].off]...)
		out = append(out, cut(ob, ofr[idx])...)
		return append(out, b[fr[idx].off+fr[idx].size:]...)
	})
}

func TestTamperSplice(t *testing.T) {
	for _, idx := range []int{0, 4} {
		f := newFixture(t).build(nEntries)
		spliceFrom(t, f, idx)
		expect(t, f.verify(nil), reason.ChainBreak, int64(idx))
	}
}

func TestTamperTimestampBackwards(t *testing.T) {
	f := newFixture(t).build(nEntries)
	fr := f.frames()[4]
	b := f.readSeg(fr.seg)
	prevTS := b[f.frames()[3].off+offTS : f.frames()[3].off+offTS+8]
	frame := b[fr.off : fr.off+fr.size]
	copy(frame[offTS:offTS+8], prevTS)
	frame[offTS+6]-- // strictly earlier than entry 3
	fixHash(frame)
	storage.FixCRC(frame)
	f.writeSeg(fr.seg, b)
	expect(t, f.verify(nil), reason.TimestampRegression, 4)
}

func TestTamperCorruptCRC(t *testing.T) {
	f := newFixture(t).build(nEntries)
	fr := flip(f, 6, fields[1], false, false)
	r := f.verify(nil)
	expect(t, r, reason.RecordCRC, 6)
	if r.Failure.Offset != int64(fr.off) {
		t.Fatal("offset")
	}
}

func TestTamperForgedCheckpoints(t *testing.T) {
	cpPath := func(f *fixture) string { return filepath.Join(f.dir, CheckpointDir, checkpointName(nEntries)) }

	t.Run("signature_byte", func(t *testing.T) {
		f := newFixture(t).build(nEntries)
		b, _ := os.ReadFile(cpPath(f))
		b[len(b)-1] ^= 1
		os.WriteFile(cpPath(f), b, 0o644)
		r := f.verify(nil)
		expect(t, r, reason.CheckpointSignature, -1)
		if r.Failure.File != checkpointName(nEntries) {
			t.Fatal("file")
		}
	})
	t.Run("body_size", func(t *testing.T) {
		f := newFixture(t).build(nEntries)
		b, _ := os.ReadFile(cpPath(f))
		b[44] ^= 1 // low byte of tree_size
		os.WriteFile(cpPath(f), b, 0o644)
		expect(t, f.verify(nil), reason.CheckpointSignature, -1)
	})
	t.Run("other_key", func(t *testing.T) {
		f := newFixture(t).build(nEntries)
		_, evil, _ := ed25519.GenerateKey(rand.Reader)
		cp := checkpoint.Sign(evil, f.id, nEntries, f.checkpointAt(nEntries).Root, time.Now())
		b, _ := cp.MarshalBinary()
		os.WriteFile(cpPath(f), b, 0o644)
		expect(t, f.verify(nil), reason.CheckpointSignature, -1)
	})
	t.Run("garbage", func(t *testing.T) {
		f := newFixture(t).build(nEntries)
		os.WriteFile(cpPath(f), []byte("junk"), 0o644)
		expect(t, f.verify(nil), reason.CheckpointDecode, -1)
	})
	t.Run("forged_witness", func(t *testing.T) {
		f := newFixture(t).build(nEntries)
		w := *f.checkpointAt(nEntries)
		w.Signature[0] ^= 1
		r := f.verify(&w)
		expect(t, r, reason.CheckpointSignature, -1)
		if r.Failure.File != "witness" {
			t.Fatal("file")
		}
	})
	t.Run("witness_other_log", func(t *testing.T) {
		f := newFixture(t).build(nEntries)
		w := checkpoint.Sign(f.priv, [32]byte{9}, 3, f.checkpointAt(3).Root, time.Now())
		expect(t, f.verify(w), reason.CheckpointLogID, -1)
	})
	t.Run("local_other_log", func(t *testing.T) {
		f := newFixture(t).build(nEntries)
		cp := checkpoint.Sign(f.priv, [32]byte{9}, nEntries, f.checkpointAt(nEntries).Root, time.Now())
		b, _ := cp.MarshalBinary()
		os.WriteFile(cpPath(f), b, 0o644)
		expect(t, f.verify(nil), reason.CheckpointLogID, -1)
	})
	t.Run("replaced_pubkey_and_resigned", func(t *testing.T) {
		// Attacker rewrites history, re-signs everything with their own key
		// and replaces pubkey.pem. The in-directory key is fooled; the
		// out-of-band key is not.
		f := newFixture(t).build(nEntries)
		evilPub, evilPriv, _ := ed25519.GenerateKey(rand.Reader)
		flip(f, 2, fields[7], true, true)
		f.rechain(2)
		os.RemoveAll(filepath.Join(f.dir, CheckpointDir))
		os.Remove(filepath.Join(f.dir, PubKeyFile))
		pem, _ := checkpoint.MarshalPublicKey(evilPub)
		os.WriteFile(filepath.Join(f.dir, PubKeyFile), pem, 0o644)
		l, err := Open(f.dir, Options{Signer: evilPriv, Sync: SyncNone})
		if err != nil {
			t.Fatal(err)
		}
		l.Checkpoint()
		l.Close()
		r, _ := Verify(f.dir, VerifyOptions{})
		if !r.OK || len(r.Warnings) == 0 {
			t.Fatalf("in-dir key should be fooled (documented) and warn: %s", r)
		}
		expect(t, f.verify(nil), reason.CheckpointSignature, -1)
	})
}

func TestTamperDeleteSegment(t *testing.T) {
	f := newFixture(t)
	o := f.opts()
	o.SegmentSize = 200 // a couple of records per segment
	l := f.open(o)
	for i := 0; i < 10; i++ {
		l.Append([]byte("x"))
	}
	l.Close()
	segs, _ := storage.ListSegments(f.dir)
	if len(segs) < 4 {
		t.Fatalf("want several segments, got %d", len(segs))
	}
	if r := f.verify(nil); !r.OK {
		t.Fatal(r)
	}
	victim := segs[1]
	os.Remove(f.segPath(victim))
	r := f.verify(nil)
	expect(t, r, reason.SeqGap, -2)
	// Truncate a non-final segment mid-record: RECORD_TRUNCATED, not torn.
	f2 := newFixture(t)
	l = f2.open(o)
	for i := 0; i < 10; i++ {
		l.Append([]byte("x"))
	}
	l.Close()
	b := f2.readSeg(segs[1])
	f2.writeSeg(segs[1], b[:len(b)-3])
	expect(t, f2.verify(nil), reason.RecordTruncated, -2)
}

func TestTornTailReportedByVerify(t *testing.T) {
	f := newFixture(t).build(3)
	fr := f.frames()
	b := f.readSeg(fr[0].seg)
	f.writeSeg(fr[0].seg, append(b, 0x00, 0x00, 0x01))
	r := f.verify(nil)
	expect(t, r, reason.TornTail, 3)
	if r.Failure.Offset != int64(len(b)) {
		t.Fatal("offset")
	}
}
