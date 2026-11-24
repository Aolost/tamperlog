// Package bench holds the benchmarks reported in the README (make bench).
package bench

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/Aolost/tamperlog"
	"github.com/Aolost/tamperlog/merkle"
)

func newLog(b *testing.B, policy tamperlog.SyncPolicy) *tamperlog.Log {
	b.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := filepath.Join(b.TempDir(), "log")
	if _, err := tamperlog.Create(dir, pub, ""); err != nil {
		b.Fatal(err)
	}
	l, err := tamperlog.Open(dir, tamperlog.Options{Signer: priv, Sync: policy, BatchSize: 64})
	if err != nil {
		b.Fatal(err)
	}
	return l
}

// BenchmarkAppend measures append throughput for each fsync policy with a
// 128-byte payload.
func BenchmarkAppend(b *testing.B) {
	payload := make([]byte, 128)
	for _, c := range []struct {
		name   string
		policy tamperlog.SyncPolicy
	}{{"fsync=every", tamperlog.SyncEvery}, {"fsync=batch64", tamperlog.SyncBatch}, {"fsync=none", tamperlog.SyncNone}} {
		b.Run(c.name, func(b *testing.B) {
			l := newLog(b, c.policy)
			defer l.Close()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := l.Append(payload); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if err := l.Sync(); err != nil {
				b.Fatal(err)
			}
		})
	}
}

func buildTree(n int) *merkle.Tree {
	t := merkle.NewTree()
	for i := 0; i < n; i++ {
		t.AppendLeafHash(merkle.LeafHash([]byte(fmt.Sprint(i))))
	}
	return t
}

var sizes = []int{1_000, 10_000, 100_000, 1_000_000}

// BenchmarkInclusion reports proof size (bytes) and verify time against n.
func BenchmarkInclusion(b *testing.B) {
	for _, n := range sizes {
		t := buildTree(n)
		root := t.Root()
		idx := uint64(n / 3)
		leaf, _ := t.LeafHash(idx)
		proof, _ := t.InclusionProof(idx, uint64(n))
		b.Run(fmt.Sprintf("n=%d/prove", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				t.InclusionProof(idx, uint64(n))
			}
		})
		b.Run(fmt.Sprintf("n=%d/verify", n), func(b *testing.B) {
			b.ReportMetric(float64(len(proof)*merkle.HashSize), "proof-bytes")
			for i := 0; i < b.N; i++ {
				if merkle.VerifyInclusion(leaf, idx, uint64(n), proof, root) != nil {
					b.Fatal("verify")
				}
			}
		})
	}
}

// BenchmarkConsistency reports proof size and verify time for m = n/2.
func BenchmarkConsistency(b *testing.B) {
	for _, n := range sizes {
		t := buildTree(n)
		m := uint64(n/2 + 7)
		oldRoot, _ := t.RootAt(m)
		newRoot := t.Root()
		proof, _ := t.ConsistencyProof(m, uint64(n))
		b.Run(fmt.Sprintf("n=%d/verify", n), func(b *testing.B) {
			b.ReportMetric(float64(len(proof)*merkle.HashSize), "proof-bytes")
			for i := 0; i < b.N; i++ {
				if merkle.VerifyConsistency(m, uint64(n), oldRoot, newRoot, proof) != nil {
					b.Fatal("verify")
				}
			}
		})
	}
}
