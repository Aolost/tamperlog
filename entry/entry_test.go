package entry

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/Aolost/tamperlog/merkle"
)

func TestGoldenV1(t *testing.T) {
	var prev merkle.Hash
	for i := range prev {
		prev[i] = byte(i)
	}
	e := Entry{Seq: 0x0102030405060708, Timestamp: 0x1112131415161718, PrevHash: prev, Payload: []byte("hi")}
	b, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := "01" + "0102030405060708" + "1112131415161718" +
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
		"00000002" + "6869"
	if hex.EncodeToString(b) != want {
		t.Fatalf("encoding changed:\n got %x\nwant %s", b, want)
	}
	// Changing this constant is a format change: bump Version instead.
	if got := Hash(b).String(); got != merkle.LeafHash(b).String() {
		t.Fatal("entry hash must equal leaf hash")
	}
	d, err := Unmarshal(b)
	if err != nil || d.Seq != e.Seq || d.Timestamp != e.Timestamp || d.PrevHash != prev || !bytes.Equal(d.Payload, e.Payload) {
		t.Fatalf("roundtrip: %+v %v", d, err)
	}
	if d.Time().UnixNano() != e.Timestamp {
		t.Fatal("Time")
	}
}

func TestDecodeRejectsNonCanonical(t *testing.T) {
	e := Entry{Seq: 1, Timestamp: 2, Payload: []byte("abc")}
	b, _ := e.MarshalBinary()
	cases := map[string]struct {
		in   []byte
		want error
	}{
		"short":    {b[:HeaderSize-1], ErrShort},
		"empty":    {nil, ErrShort},
		"version":  {append([]byte{2}, b[1:]...), ErrVersion},
		"trailing": {append(append([]byte{}, b...), 0), ErrLength},
		"missing":  {b[:len(b)-1], ErrLength},
	}
	big := append([]byte{}, b[:HeaderSize]...)
	big[49], big[50], big[51], big[52] = 0x01, 0x00, 0x00, 0x01 // > MaxPayload
	cases["toolarge"] = struct {
		in   []byte
		want error
	}{big, ErrTooLarge}
	for name, c := range cases {
		if _, err := Unmarshal(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", name, err, c.want)
		}
	}
	if _, err := (&Entry{Payload: make([]byte, MaxPayload+1)}).MarshalBinary(); !errors.Is(err, ErrTooLarge) {
		t.Fatal("encode too large")
	}
}

func TestChain(t *testing.T) {
	var id, other [32]byte
	id[0], other[0] = 1, 2
	if GenesisHash(id) == GenesisHash(other) {
		t.Fatal("genesis must depend on log id")
	}
	c := NewChain(id)
	var hashes []merkle.Hash
	prev := GenesisHash(id)
	for i := uint64(0); i < 5; i++ {
		e := Entry{Seq: i, Timestamp: int64(i * 10), PrevHash: prev, Payload: []byte{byte(i)}}
		b, _ := e.MarshalBinary()
		h := Hash(b)
		if err := c.Add(&e, h); err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, h)
		prev = h
	}
	if c.Next() != 5 || c.Head() != prev || c.LastTimestamp() != 40 {
		t.Fatal("chain state")
	}
	check := func(e Entry, reason string, seq uint64) {
		t.Helper()
		err := NewChainAt(c).Add(&e, merkle.Hash{})
		var ce *ChainError
		if !errors.As(err, &ce) || ce.Reason != reason || ce.Seq != seq {
			t.Fatalf("want %s@%d got %v", reason, seq, err)
		}
		if ce.Error() == "" {
			t.Fatal("empty error")
		}
	}
	check(Entry{Seq: 6, Timestamp: 50, PrevHash: prev}, ReasonSeq, 5)
	check(Entry{Seq: 5, Timestamp: 50, PrevHash: hashes[0]}, ReasonPrevHash, 5)
	check(Entry{Seq: 5, Timestamp: 39, PrevHash: prev}, ReasonTimestamp, 5)
	// Equal timestamps are allowed.
	if err := NewChainAt(c).Add(&Entry{Seq: 5, Timestamp: 40, PrevHash: prev}, merkle.Hash{}); err != nil {
		t.Fatal(err)
	}
	// Seq 0 from another log breaks the chain.
	e0 := Entry{Seq: 0, PrevHash: GenesisHash(other)}
	if err := NewChain(id).Add(&e0, merkle.Hash{}); err == nil {
		t.Fatal("spliced genesis accepted")
	}
}

// NewChainAt copies a chain state (test helper).
func NewChainAt(c *Chain) *Chain { cp := *c; return &cp }

func FuzzDecodeEntry(f *testing.F) {
	e := Entry{Seq: 7, Timestamp: 99, Payload: []byte("seed")}
	b, _ := e.MarshalBinary()
	f.Add(b)
	f.Add([]byte{})
	f.Add(make([]byte, HeaderSize))
	f.Fuzz(func(t *testing.T, in []byte) {
		d, err := Unmarshal(in)
		if err != nil {
			return
		}
		out, err := d.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, in) {
			t.Fatalf("non-canonical decode: %x -> %x", in, out)
		}
	})
}
