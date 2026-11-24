package merkle

// Cross-check against an independent RFC 6962 implementation:
// golang.org/x/mod/sumdb/tlog (the Go checksum database). This is a test-only
// dependency. If the two disagree, the test fails and the disagreement must be
// explained, never papered over.

import (
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

type tlogStore struct{ hashes []tlog.Hash }

func (s *tlogStore) ReadHashes(idx []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(idx))
	for i, x := range idx {
		out[i] = s.hashes[x]
	}
	return out, nil
}

func buildBoth(t *testing.T, n int64) (*Tree, *tlogStore) {
	t.Helper()
	tr := NewTree()
	st := &tlogStore{}
	for i := int64(0); i < n; i++ {
		d := leafData(uint64(i))
		if Hash(tlog.RecordHash(d)) != LeafHash(d) {
			t.Fatalf("leaf hash differs at %d", i)
		}
		hs, err := tlog.StoredHashes(i, d, st)
		if err != nil {
			t.Fatal(err)
		}
		st.hashes = append(st.hashes, hs...)
		tr.AppendLeafHash(LeafHash(d))
	}
	return tr, st
}

func toTlog(p []Hash) []tlog.Hash {
	out := make([]tlog.Hash, len(p))
	for i := range p {
		out[i] = tlog.Hash(p[i])
	}
	return out
}

func fromTlog(p []tlog.Hash) []Hash {
	out := make([]Hash, len(p))
	for i := range p {
		out[i] = Hash(p[i])
	}
	return out
}

func TestCrossCheckTlog(t *testing.T) {
	const maxN = 600
	tr, st := buildBoth(t, maxN)
	var a, b Hash
	if NodeHash(a, b) != Hash(tlog.NodeHash(tlog.Hash(a), tlog.Hash(b))) {
		t.Fatal("node hash differs")
	}
	for n := int64(1); n <= maxN; n++ {
		want, err := tlog.TreeHash(n, st)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := tr.RootAt(uint64(n))
		if got != Hash(want) {
			t.Fatalf("root differs at n=%d", n)
		}
		// Inclusion: compare a spread of indices (all of them for small n).
		step := int64(1)
		if n > 64 {
			step = n/17 + 1
		}
		for i := int64(0); i < n; i += step {
			theirs, err := tlog.ProveRecord(n, i, st)
			if err != nil {
				t.Fatal(err)
			}
			ours, _ := tr.InclusionProof(uint64(i), uint64(n))
			if len(ours) != len(theirs) {
				t.Fatalf("inclusion len differs n=%d i=%d: %d vs %d", n, i, len(ours), len(theirs))
			}
			for k := range ours {
				if ours[k] != Hash(theirs[k]) {
					t.Fatalf("inclusion differs n=%d i=%d k=%d", n, i, k)
				}
			}
			leaf, _ := tr.LeafHash(uint64(i))
			if err := VerifyInclusion(leaf, uint64(i), uint64(n), fromTlog(theirs), got); err != nil {
				t.Fatalf("our verifier rejects tlog proof: %v", err)
			}
			if err := tlog.CheckRecord(toTlog(ours), n, want, i, tlog.Hash(leaf)); err != nil {
				t.Fatalf("tlog rejects our proof: %v", err)
			}
		}
		// Consistency: compare several old sizes.
		for _, m := range []int64{1, 2, 3, n / 3, n / 2, n - 1} {
			if m < 1 || m >= n {
				continue
			}
			theirs, err := tlog.ProveTree(n, m, st)
			if err != nil {
				t.Fatal(err)
			}
			ours, _ := tr.ConsistencyProof(uint64(m), uint64(n))
			if len(ours) != len(theirs) {
				t.Fatalf("consistency len differs m=%d n=%d", m, n)
			}
			for k := range ours {
				if ours[k] != Hash(theirs[k]) {
					t.Fatalf("consistency differs m=%d n=%d k=%d", m, n, k)
				}
			}
			old, _ := tr.RootAt(uint64(m))
			if err := VerifyConsistency(uint64(m), uint64(n), old, got, fromTlog(theirs)); err != nil {
				t.Fatalf("our verifier rejects tlog consistency proof m=%d n=%d: %v", m, n, err)
			}
			if err := tlog.CheckTree(toTlog(ours), n, want, m, tlog.Hash(old)); err != nil {
				t.Fatalf("tlog rejects our consistency proof m=%d n=%d: %v", m, n, err)
			}
		}
	}
}
