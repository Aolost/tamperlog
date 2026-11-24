package merkle

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

func leafData(i uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], i)
	return b[:]
}

func buildTree(n uint64) *Tree {
	t := NewTree()
	for i := uint64(0); i < n; i++ {
		t.AppendLeafHash(LeafHash(leafData(i)))
	}
	return t
}

// naiveRoot is a direct transcription of the RFC 6962 MTH definition, used as
// an oracle for the optimized Tree.
func naiveRoot(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		return EmptyRoot
	case 1:
		return leaves[0]
	}
	k := largestPow2Less(uint64(len(leaves)))
	return NodeHash(naiveRoot(leaves[:k]), naiveRoot(leaves[k:]))
}

func TestKnownVectors(t *testing.T) {
	// RFC 6962 empty tree hash.
	if EmptyRoot.String() != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty root %s", EmptyRoot)
	}
	// Leaf hash of the empty string: SHA-256(0x00).
	if got := LeafHash(nil).String(); got != "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" {
		t.Fatalf("leaf(\"\") = %s", got)
	}
	want := Hash(sha256.Sum256(append(append([]byte{1}, make([]byte, 32)...), make([]byte, 32)...)))
	if NodeHash(Hash{}, Hash{}) != want {
		t.Fatal("node hash")
	}
}

func TestRootMatchesNaive(t *testing.T) {
	tr := NewTree()
	var leaves []Hash
	if tr.Root() != EmptyRoot {
		t.Fatal("empty")
	}
	for i := uint64(0); i < 300; i++ {
		h := LeafHash(leafData(i))
		leaves = append(leaves, h)
		tr.AppendLeafHash(h)
		if got, want := tr.Root(), naiveRoot(leaves); got != want {
			t.Fatalf("n=%d root mismatch", i+1)
		}
		for m := uint64(0); m <= i+1; m += 7 {
			r, err := tr.RootAt(m)
			if err != nil || r != naiveRoot(leaves[:m]) {
				t.Fatalf("RootAt(%d) of %d wrong", m, i+1)
			}
		}
	}
	if _, err := tr.RootAt(301); !errors.Is(err, ErrBadRange) {
		t.Fatal("RootAt beyond size")
	}
	if _, err := tr.LeafHash(300); !errors.Is(err, ErrBadRange) {
		t.Fatal("LeafHash beyond size")
	}
	if h, _ := tr.LeafHash(3); h != leaves[3] {
		t.Fatal("LeafHash")
	}
}

// Property: for every n <= 2000 and every index < n, the inclusion proof verifies.
func TestInclusionAllSizes(t *testing.T) {
	maxN := uint64(2000)
	tr := buildTree(maxN)
	for n := uint64(1); n <= maxN; n++ {
		root, _ := tr.RootAt(n)
		for i := uint64(0); i < n; i++ {
			p, err := tr.InclusionProof(i, n)
			if err != nil {
				t.Fatal(err)
			}
			leaf, _ := tr.LeafHash(i)
			if err := VerifyInclusion(leaf, i, n, p, root); err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
		}
	}
}

// Property: for every 1 <= m < n <= 300 the consistency proof verifies.
func TestConsistencyAllPairs(t *testing.T) {
	maxN := uint64(300)
	tr := buildTree(maxN)
	roots := make([]Hash, maxN+1)
	for n := range roots {
		roots[n], _ = tr.RootAt(uint64(n))
	}
	for n := uint64(1); n <= maxN; n++ {
		for m := uint64(1); m < n; m++ {
			p, err := tr.ConsistencyProof(m, n)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyConsistency(m, n, roots[m], roots[n], p); err != nil {
				t.Fatalf("m=%d n=%d: %v", m, n, err)
			}
			// Wrong old root or swapped roots must fail.
			if m > 1 && VerifyConsistency(m, n, roots[m-1], roots[n], p) == nil {
				t.Fatalf("m=%d n=%d accepted wrong old root", m, n)
			}
		}
		// m == n: empty proof, equal roots.
		p, _ := tr.ConsistencyProof(n, n)
		if len(p) != 0 || VerifyConsistency(n, n, roots[n], roots[n], p) != nil {
			t.Fatalf("m=n=%d", n)
		}
	}
}

func TestEdgeCases(t *testing.T) {
	tr := buildTree(10)
	root := tr.Root()
	if _, err := tr.InclusionProof(10, 10); !errors.Is(err, ErrBadRange) {
		t.Fatal("index == size")
	}
	if _, err := tr.InclusionProof(0, 11); !errors.Is(err, ErrBadRange) {
		t.Fatal("size > tree")
	}
	if _, err := tr.ConsistencyProof(5, 11); !errors.Is(err, ErrBadRange) {
		t.Fatal("n > tree")
	}
	if _, err := tr.ConsistencyProof(6, 5); !errors.Is(err, ErrBadRange) {
		t.Fatal("m > n")
	}
	if p, _ := tr.ConsistencyProof(0, 5); len(p) != 0 {
		t.Fatal("m=0 proof not empty")
	}
	if err := VerifyConsistency(0, 10, EmptyRoot, root, nil); err != nil {
		t.Fatal(err)
	}
	if VerifyConsistency(0, 10, root, root, nil) == nil {
		t.Fatal("m=0 with non-empty old root")
	}
	if VerifyConsistency(0, 10, EmptyRoot, root, []Hash{{}}) == nil {
		t.Fatal("m=0 with proof")
	}
	if VerifyConsistency(11, 10, root, root, nil) == nil {
		t.Fatal("m>n")
	}
	if VerifyConsistency(10, 10, root, root, []Hash{{}}) == nil {
		t.Fatal("m=n with proof")
	}
	if !errors.Is(VerifyConsistency(10, 10, root, Hash{}, nil), ErrRootMismatch) {
		t.Fatal("m=n roots differ")
	}
	if VerifyConsistency(3, 10, root, root, nil) == nil {
		t.Fatal("empty proof for m<n")
	}
	if VerifyConsistency(3, 10, root, root, make([]Hash, MaxProofLen+1)) == nil {
		t.Fatal("oversized proof")
	}
	if VerifyInclusion(Hash{}, 0, 10, make([]Hash, MaxProofLen+1), root) == nil {
		t.Fatal("oversized inclusion proof")
	}
	if VerifyInclusion(Hash{}, 10, 10, nil, root) == nil {
		t.Fatal("index >= size")
	}
	// Size-1 tree: empty proof, root == leaf.
	one := buildTree(1)
	l, _ := one.LeafHash(0)
	if VerifyInclusion(l, 0, 1, nil, one.Root()) != nil {
		t.Fatal("size 1")
	}
	if VerifyInclusion(l, 0, 1, []Hash{{}}, one.Root()) == nil {
		t.Fatal("size 1 with extra hash")
	}
	if _, err := ParseHash("zz"); err == nil {
		t.Fatal("ParseHash")
	}
	if h, err := ParseHash(root.String()); err != nil || h != root {
		t.Fatal("ParseHash roundtrip")
	}
}

// Property: any single-byte mutation of a proof hash or root, and any wrong
// index/size, truncation or extension, makes verification fail.
func TestProofMutation(t *testing.T) {
	tr := buildTree(300)
	cases := [][2]uint64{{0, 1}, {0, 2}, {1, 2}, {5, 7}, {0, 8}, {7, 8}, {12, 13}, {100, 255}, {255, 256}, {0, 300}, {299, 300}, {150, 300}}
	xors := []byte{0x01, 0x80, 0xFF}
	for _, c := range cases {
		i, n := c[0], c[1]
		root, _ := tr.RootAt(n)
		leaf, _ := tr.LeafHash(i)
		p, _ := tr.InclusionProof(i, n)
		if VerifyInclusion(leaf, i, n, p, root) != nil {
			t.Fatal("baseline")
		}
		for k := range p {
			for b := 0; b < HashSize; b++ {
				for _, x := range xors {
					q := append([]Hash(nil), p...)
					q[k][b] ^= x
					if VerifyInclusion(leaf, i, n, q, root) == nil {
						t.Fatalf("inclusion (%d,%d) mutated proof[%d][%d]^%x accepted", i, n, k, b, x)
					}
				}
			}
		}
		for b := 0; b < HashSize; b++ {
			for _, x := range xors {
				r := root
				r[b] ^= x
				if VerifyInclusion(leaf, i, n, p, r) == nil {
					t.Fatal("mutated root accepted")
				}
				l := leaf
				l[b] ^= x
				if VerifyInclusion(l, i, n, p, root) == nil {
					t.Fatal("mutated leaf accepted")
				}
			}
		}
		for _, wi := range []uint64{i + 1, i ^ 1, i + 64, i + n} {
			if wi != i && wi < n+70 && VerifyInclusion(leaf, wi, n, p, root) == nil {
				t.Fatalf("wrong index %d for (%d,%d) accepted", wi, i, n)
			}
		}
		// Note: a wrong *size* with the *same* root is not necessarily rejected
		// here. RFC 9162 verification recomputes a root from (index, size,
		// path); e.g. the proof for (5,7) yields the same computation for
		// (5,8). The size is authenticated only by the signed checkpoint that
		// pairs it with the root, so the binding is enforced (and tested) at the
		// bundle level, where size must equal the checkpoint's tree size.
		if len(p) > 0 && VerifyInclusion(leaf, i, n, p[:len(p)-1], root) == nil {
			t.Fatal("truncated proof accepted")
		}
		if VerifyInclusion(leaf, i, n, append(append([]Hash(nil), p...), Hash{}), root) == nil {
			t.Fatal("extended proof accepted")
		}
	}

	pairs := [][2]uint64{{1, 2}, {1, 3}, {2, 3}, {3, 7}, {4, 8}, {4, 9}, {7, 8}, {6, 300}, {128, 300}, {255, 256}, {256, 299}}
	for _, c := range pairs {
		m, n := c[0], c[1]
		or, _ := tr.RootAt(m)
		nr, _ := tr.RootAt(n)
		p, _ := tr.ConsistencyProof(m, n)
		if VerifyConsistency(m, n, or, nr, p) != nil {
			t.Fatal("baseline")
		}
		for k := range p {
			for b := 0; b < HashSize; b++ {
				for _, x := range xors {
					q := append([]Hash(nil), p...)
					q[k][b] ^= x
					if VerifyConsistency(m, n, or, nr, q) == nil {
						t.Fatalf("consistency (%d,%d) mutated proof[%d][%d] accepted", m, n, k, b)
					}
				}
			}
		}
		for b := 0; b < HashSize; b++ {
			for _, x := range xors {
				o2, n2 := or, nr
				o2[b] ^= x
				n2[b] ^= x
				if VerifyConsistency(m, n, o2, nr, p) == nil || VerifyConsistency(m, n, or, n2, p) == nil {
					t.Fatalf("consistency (%d,%d) mutated root accepted", m, n)
				}
			}
		}
		if len(p) > 1 && VerifyConsistency(m, n, or, nr, p[:len(p)-1]) == nil {
			t.Fatal("truncated consistency proof accepted")
		}
		if VerifyConsistency(m, n, or, nr, append(append([]Hash(nil), p...), Hash{})) == nil {
			t.Fatal("extended consistency proof accepted")
		}
	}
}

func TestConcurrentTree(t *testing.T) {
	tr := NewTree()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := uint64(0); i < 2000; i++ {
			tr.AppendLeafHash(LeafHash(leafData(i)))
		}
	}()
	for r := 0; r < 4; r++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
				}
				n := tr.Size()
				if n == 0 {
					continue
				}
				root, _ := tr.RootAt(n)
				p, err := tr.InclusionProof(n-1, n)
				if err != nil {
					panic(err)
				}
				l, _ := tr.LeafHash(n - 1)
				if VerifyInclusion(l, n-1, n, p, root) != nil {
					panic("concurrent proof failed")
				}
			}
		}()
	}
	<-done
}

func BenchmarkAppend(b *testing.B) {
	tr := NewTree()
	h := LeafHash([]byte("x"))
	for i := 0; i < b.N; i++ {
		tr.AppendLeafHash(h)
	}
}
