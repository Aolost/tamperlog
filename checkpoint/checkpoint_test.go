package checkpoint

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Aolost/tamperlog/merkle"
)

func testKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignVerifyRoundtrip(t *testing.T) {
	pub, priv := testKey(t)
	other, _ := testKey(t)
	var id [32]byte
	id[3] = 9
	root := merkle.LeafHash([]byte("x"))
	ts := time.Unix(1700000000, 5)
	c := Sign(priv, id, 42, root, ts)
	if err := c.Verify(pub); err != nil {
		t.Fatal(err)
	}
	if !c.Time().Equal(ts) {
		t.Fatal("time")
	}
	if c.Verify(other) == nil || c.Verify(nil) == nil {
		t.Fatal("wrong key accepted")
	}
	b, _ := c.MarshalBinary()
	if len(b) != Size {
		t.Fatalf("size %d", len(b))
	}
	d, err := Unmarshal(b)
	if err != nil || *d != *c {
		t.Fatal("roundtrip")
	}
	// Every single-byte mutation must break decoding or the signature.
	for i := range b {
		m := append([]byte(nil), b...)
		m[i] ^= 0x01
		d, err := Unmarshal(m)
		if err == nil && d.Verify(pub) == nil {
			t.Fatalf("mutation at byte %d accepted", i)
		}
	}
	if _, err := Unmarshal(b[:Size-1]); !errors.Is(err, ErrDecode) {
		t.Fatal("short")
	}
	bad := append([]byte(nil), b...)
	bad[4] = 2
	if _, err := Unmarshal(bad); !errors.Is(err, ErrDecode) {
		t.Fatal("version")
	}
}

func TestAtomicWriteAndRead(t *testing.T) {
	_, priv := testKey(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "a.ck")
	c := Sign(priv, [32]byte{}, 1, merkle.Hash{}, time.Now())
	b, _ := c.MarshalBinary()
	if err := WriteFileAtomic(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp left behind")
	}
	got, err := ReadFile(p)
	if err != nil || *got != *c {
		t.Fatal("ReadFile")
	}
	if _, err := ReadFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing")
	}
	if err := WriteFileAtomic(filepath.Join(dir, "nodir", "x"), b, 0o644); err == nil {
		t.Fatal("write into missing dir")
	}
	if err := SyncDir(filepath.Join(dir, "nodir")); err == nil {
		t.Fatal("sync missing dir")
	}
}

func TestKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k.pem")
	pub, err := GenerateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	if _, err := GenerateKey(p); err == nil {
		t.Fatal("GenerateKey overwrote existing key")
	}
	priv, err := LoadPrivateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		t.Fatal("pub mismatch")
	}
	raw, _ := os.ReadFile(p)
	for _, mode := range []os.FileMode{0o640, 0o644, 0o604, 0o660, 0o601} {
		os.Chmod(p, mode)
		_, err := LoadPrivateKey(p)
		if !errors.Is(err, ErrKeyPermissions) {
			t.Fatalf("mode %o accepted: %v", mode, err)
		}
		if strings.Contains(err.Error(), string(raw[30:60])) {
			t.Fatal("key material in error")
		}
	}
	os.Chmod(p, 0o400)
	if _, err := LoadPrivateKey(p); err != nil {
		t.Fatalf("0400 rejected: %v", err)
	}
	if _, err := LoadPrivateKey(dir); !errors.Is(err, ErrKeyNotRegular) {
		t.Fatalf("dir: %v", err)
	}
	if _, err := LoadPrivateKey(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("missing")
	}
	garbage := filepath.Join(dir, "g.pem")
	os.WriteFile(garbage, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600)
	if _, err := LoadPrivateKey(garbage); !errors.Is(err, ErrKeyFormat) {
		t.Fatal("garbage")
	}
	os.WriteFile(garbage, []byte("not pem"), 0o600)
	if _, err := LoadPrivateKey(garbage); !errors.Is(err, ErrKeyFormat) {
		t.Fatal("not pem")
	}

	pemPub, err := MarshalPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pp := filepath.Join(dir, "k.pub")
	os.WriteFile(pp, pemPub, 0o644)
	got, err := LoadPublicKey(pp)
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatal("public roundtrip")
	}
	if _, err := ParsePublicKey([]byte("x")); err == nil {
		t.Fatal("bad pub")
	}
	if _, err := ParsePublicKey(raw); err == nil {
		t.Fatal("private parsed as public")
	}
	if _, err := ParsePublicKey([]byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")); err == nil {
		t.Fatal("bad der")
	}
	if _, err := LoadPublicKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing pub")
	}
}

func FuzzDecodeCheckpoint(f *testing.F) {
	_, priv := testKey(f)
	c := Sign(priv, [32]byte{1}, 5, merkle.Hash{2}, time.Unix(1, 0))
	b, _ := c.MarshalBinary()
	f.Add(b)
	f.Add([]byte("TLCK"))
	f.Fuzz(func(t *testing.T, in []byte) {
		c, err := Unmarshal(in)
		if err != nil {
			return
		}
		out, _ := c.MarshalBinary()
		if !bytes.Equal(out, in) {
			t.Fatal("non-canonical")
		}
	})
}
