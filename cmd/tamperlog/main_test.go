package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type env struct {
	t   *testing.T
	dir string
	key string
	tmp string
}

func newEnv(t *testing.T) *env {
	tmp := t.TempDir()
	return &env{t: t, dir: filepath.Join(tmp, "log"), key: filepath.Join(tmp, "signing.pem"), tmp: tmp}
}

func (e *env) run(stdin string, args ...string) (int, string, string) {
	e.t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"--dir", e.dir}, args...), strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func (e *env) must(args ...string) string {
	e.t.Helper()
	code, out, errs := e.run("", args...)
	if code != 0 {
		e.t.Fatalf("%v: exit %d\n%s%s", args, code, out, errs)
	}
	return out
}

func (e *env) expectFail(want string, args ...string) string {
	e.t.Helper()
	code, out, errs := e.run("", args...)
	if code != 1 || !strings.Contains(out, "FAIL reason="+want) {
		e.t.Fatalf("%v: want exit 1 reason=%s, got %d\n%s%s", args, want, code, out, errs)
	}
	return out
}

func TestCLIEndToEnd(t *testing.T) {
	e := newEnv(t)
	pub := e.key + ".pub"
	out := e.must("init", "--key", e.key)
	if !strings.Contains(out, "generated key") {
		t.Fatal(out)
	}
	st, _ := os.Stat(e.key)
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatal("key mode")
	}
	if code, _, _ := e.run("", "init", "--key", e.key); code != 2 {
		t.Fatal("init twice")
	}
	e.must("append", "first event", "second event")
	if code, out, _ := e.run("third\n\nfourth\n", "append", "--stdin", "--batch"); code != 0 || !strings.Contains(out, "count=2 size=4 checkpoint=4") {
		t.Fatalf("stdin append: %s", out)
	}
	witness := filepath.Join(e.tmp, "witness.ck")
	out = e.must("checkpoint", "-o", witness)
	if !strings.Contains(out, "checkpoint size=4") {
		t.Fatal(out)
	}
	out = e.must("verify", "--pubkey", pub, "--against", witness)
	if !strings.HasPrefix(out, "OK size=4") || !strings.Contains(out, "witness=ok") {
		t.Fatal(out)
	}
	if code, out, _ := e.run("", "verify", "--pubkey", pub, "--json"); code != 0 || !strings.Contains(out, `"ok": true`) {
		t.Fatal(out)
	}
	// Without --pubkey: works but warns.
	if code, _, errs := e.run("", "verify"); code != 0 || !strings.Contains(errs, "warning") {
		t.Fatal(errs)
	}

	proof := filepath.Join(e.tmp, "p.proof")
	e.must("prove-inclusion", "-o", proof, "2")
	out = e.must("verify-inclusion", "--pubkey", pub, proof)
	if !strings.Contains(out, `payload="third"`) {
		t.Fatal(out)
	}
	cproof := filepath.Join(e.tmp, "c.proof")
	e.must("prove-consistency", "-o", cproof, "2", "latest")
	if out := e.must("verify-consistency", "--pubkey", pub, cproof); !strings.HasPrefix(out, "OK old=2 new=4") {
		t.Fatal(out)
	}
	// Witness file as OLD.
	e.must("append", "fifth")
	e.must("prove-consistency", "-o", cproof, witness, "latest")
	e.must("verify-consistency", "--pubkey", pub, cproof)

	// Default output names.
	wd, _ := os.Getwd()
	os.Chdir(e.tmp)
	e.must("prove-inclusion", "0")
	e.must("prove-consistency", "2", "5")
	os.Chdir(wd)
	if _, err := os.Stat(filepath.Join(e.tmp, "inclusion-0-5.proof")); err != nil {
		t.Fatal(err)
	}

	out = e.must("export", "--json")
	var doc struct {
		Size    int `json:"size"`
		Entries []struct {
			PayloadText string `json:"payload_text"`
		} `json:"entries"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.Size != 5 || doc.Entries[4].PayloadText != "fifth" {
		t.Fatalf("export: %v %s", err, out)
	}

	// Tampered proofs fail with a reason code.
	data, _ := os.ReadFile(proof)
	data[len(data)-1] ^= 1
	os.WriteFile(proof, data, 0o644)
	e.expectFail("PROOF_INVALID", "verify-inclusion", "--pubkey", pub, proof)
	os.WriteFile(proof, []byte("garbage"), 0o644)
	e.expectFail("PROOF_DECODE", "verify-inclusion", "--pubkey", pub, proof)
	os.WriteFile(cproof, []byte("garbage"), 0o644)
	e.expectFail("PROOF_DECODE", "verify-consistency", "--pubkey", pub, cproof)

	// Tamper with the log: flip a payload byte without fixing the CRC.
	seg := filepath.Join(e.dir, "segments", "00000000000000000000.seg")
	b, _ := os.ReadFile(seg)
	b[70] ^= 1
	os.WriteFile(seg, b, 0o644)
	out = e.expectFail("RECORD_CRC", "verify", "--pubkey", pub)
	if !strings.Contains(out, "seq=0") || !strings.Contains(out, "offset=0") {
		t.Fatal(out)
	}
	// Open refuses, exits 1 with the same reason.
	if code, out, errs := e.run("", "append", "x"); code != 1 || !strings.Contains(out, "RECORD_CRC") || !strings.Contains(errs, "refusing") {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	e.expectFail("RECORD_CRC", "export", "--json")
	b[70] ^= 1
	os.WriteFile(seg, b, 0o644)

	// Rollback: truncate to an exact record boundary and drop newer checkpoints.
	e.must("verify", "--pubkey", pub)
	os.WriteFile(filepath.Join(e.tmp, "w5.ck"), mustRead(t, filepath.Join(e.dir, "checkpoints", "00000000000000000005.ck")), 0o644)
	os.Remove(filepath.Join(e.dir, "checkpoints", "00000000000000000005.ck"))
	lastFrame := 8 + 53 + len("fifth") + 32
	os.WriteFile(seg, b[:len(b)-lastFrame], 0o644)
	e.must("verify", "--pubkey", pub)
	e.expectFail("WITNESS_ROLLBACK", "verify", "--pubkey", pub, "--against", filepath.Join(e.tmp, "w5.ck"))
	os.WriteFile(witness, []byte("junk"), 0o644)
	e.expectFail("CHECKPOINT_DECODE", "verify", "--pubkey", pub, "--against", witness)
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCLIUsageErrors(t *testing.T) {
	e := newEnv(t)
	for _, args := range [][]string{
		{},
		{"bogus"},
		{"--nope"},
		{"init"},
		{"init", "--bad"},
		{"append", "x"},          // no log
		{"verify"},               // no log
		{"checkpoint"},           // no log
		{"prove-inclusion"},      // missing arg
		{"prove-inclusion", "x"}, // bad seq
		{"prove-inclusion", "0"}, // no log
		{"verify-inclusion"},
		{"verify-inclusion", "/nonexistent"},
		{"prove-consistency", "1"},
		{"prove-consistency", "1", "2"},
		{"verify-consistency"},
		{"verify-consistency", "/nonexistent"},
		{"export"},
		{"export", "--json"},
		{"verify", "--pubkey", "/nonexistent"},
	} {
		if code, _, _ := e.run("", args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	e.must("init", "--key", e.key)
	for _, args := range [][]string{
		{"append"},               // nothing to append
		{"prove-inclusion", "0"}, // not covered
		{"prove-consistency", "1", "latest"},
		{"prove-consistency", "latest", "1"},
		{"verify", "--against", "/nonexistent"},
		{"verify-inclusion", "--pubkey", "/nonexistent", "/etc/hostname"},
		{"checkpoint", "--key", "/nonexistent"},
		{"append", "--key", "/nonexistent", "x"},
	} {
		if code, _, _ := e.run("", args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	// Loose key permissions are refused, and the key is never echoed.
	os.Chmod(e.key, 0o644)
	code, out, errs := e.run("", "append", "x")
	if code != 2 || !strings.Contains(errs, "permissions") || strings.Contains(out+errs, "PRIVATE KEY") {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	if code, _, _ := e.run("", "init", "--key", e.key); code != 2 {
		t.Fatal("init with loose existing key")
	}
	os.Chmod(e.key, 0o600)
	// Re-init into a new dir with the existing key.
	e2 := &env{t: t, dir: filepath.Join(e.tmp, "log2"), key: e.key, tmp: e.tmp}
	if out := e2.must("init", "--key", e.key); !strings.Contains(out, "using existing key") {
		t.Fatal(out)
	}
	// A log without a key path appends but warns.
	e3 := &env{t: t, dir: filepath.Join(e.tmp, "log3"), tmp: e.tmp}
	os.MkdirAll(e3.dir, 0o755)
	e3.must("init", "--key", filepath.Join(e.tmp, "k3.pem"))
	meta := filepath.Join(e3.dir, "meta.json")
	m, _ := os.ReadFile(meta)
	os.WriteFile(meta, []byte(strings.Replace(string(m), `"key_path"`, `"unused"`, 1)), 0o644)
	if code, _, errs := e3.run("", "append", "x"); code != 0 || !strings.Contains(errs, "no signing key") {
		t.Fatal(errs)
	}
	if code, _, _ := e3.run("", "checkpoint"); code != 2 {
		t.Fatal("checkpoint without key")
	}
	if code, _, _ := e3.run("", "export"); code != 2 {
		t.Fatal("export without --json")
	}
}
