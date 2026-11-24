// Command tamperlog is the CLI for the tamperlog tamper-evident audit log.
//
// Exit status: 0 success / verified, 1 integrity or verification failure
// (a machine-readable "FAIL reason=..." line is printed), 2 usage or I/O error.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/Aolost/tamperlog"
	"github.com/Aolost/tamperlog/checkpoint"
	"github.com/Aolost/tamperlog/entry"
	"github.com/Aolost/tamperlog/reason"
)

const (
	exitOK   = 0
	exitFail = 1
	exitErr  = 2
)

const usage = `usage: tamperlog [--dir DIR] <command> [flags] [args]

commands:
  init --key PATH                       create a log; generate the key at PATH if absent (mode 0600)
  append [--stdin] [MESSAGE...]         append entries (one per argument, or one per stdin line)
  verify [--pubkey P] [--against CP] [--json]
                                        verify the log; --against is a witness checkpoint
  checkpoint [-o FILE]                  sign the current tree head; -o copies it out for a witness
  prove-inclusion SEQ [-o FILE]         write an inclusion proof against the latest checkpoint
  verify-inclusion PROOF [--pubkey P]   verify an inclusion proof offline
  prove-consistency OLD NEW [-o FILE]   OLD/NEW: a size with a local checkpoint, "latest", or a checkpoint file
  verify-consistency PROOF [--pubkey P] verify a consistency proof offline
  export --json                         dump entries and checkpoints as JSON (not hashed, for humans/tools)

DIR defaults to $TAMPERLOG_DIR, then ./.tamperlog
`

type cli struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	dir            string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	c := &cli{stdin: stdin, stdout: stdout, stderr: stderr, dir: os.Getenv("TAMPERLOG_DIR")}
	if c.dir == "" {
		c.dir = ".tamperlog"
	}
	g := flag.NewFlagSet("tamperlog", flag.ContinueOnError)
	g.SetOutput(stderr)
	g.StringVar(&c.dir, "dir", c.dir, "log directory")
	g.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := g.Parse(args); err != nil {
		return exitErr
	}
	if g.NArg() == 0 {
		fmt.Fprint(stderr, usage)
		return exitErr
	}
	cmds := map[string]func([]string) int{
		"init":               c.cmdInit,
		"append":             c.cmdAppend,
		"verify":             c.cmdVerify,
		"checkpoint":         c.cmdCheckpoint,
		"prove-inclusion":    c.cmdProveInclusion,
		"verify-inclusion":   c.cmdVerifyInclusion,
		"prove-consistency":  c.cmdProveConsistency,
		"verify-consistency": c.cmdVerifyConsistency,
		"export":             c.cmdExport,
	}
	fn, ok := cmds[g.Arg(0)]
	if !ok {
		fmt.Fprintf(stderr, "tamperlog: unknown command %q\n%s", g.Arg(0), usage)
		return exitErr
	}
	return fn(g.Args()[1:])
}

func (c *cli) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.StringVar(&c.dir, "dir", c.dir, "log directory")
	return fs
}

func (c *cli) errorf(format string, a ...any) int {
	fmt.Fprintf(c.stderr, "tamperlog: "+format+"\n", a...)
	return exitErr
}

// fail prints a machine-readable failure line and returns exit status 1.
func (c *cli) fail(f *tamperlog.Finding) int {
	fmt.Fprintln(c.stdout, f.String())
	return exitFail
}

// openErr maps an Open error: corruption is an integrity failure (exit 1),
// anything else is an operational error (exit 2).
func (c *cli) openErr(err error) int {
	var ce *tamperlog.CorruptionError
	if errors.As(err, &ce) {
		fmt.Fprintln(c.stderr, "tamperlog: refusing to open log: history cannot be vouched for")
		return c.fail(&ce.Finding)
	}
	return c.errorf("%v", err)
}

func (c *cli) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(c.stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func (c *cli) cmdInit(args []string) int {
	fs := c.flags("init")
	keyPath := fs.String("key", "", "private key path (generated with mode 0600 if absent)")
	if fs.Parse(args) != nil {
		return exitErr
	}
	if *keyPath == "" {
		return c.errorf("init: --key PATH is required")
	}
	abs, err := filepath.Abs(*keyPath)
	if err != nil {
		return c.errorf("%v", err)
	}
	var pub ed25519.PublicKey
	if _, err := os.Stat(abs); err == nil {
		priv, err := checkpoint.LoadPrivateKey(abs)
		if err != nil {
			return c.errorf("init: %v", err)
		}
		pub = priv.Public().(ed25519.PublicKey)
		fmt.Fprintf(c.stdout, "using existing key %s\n", *keyPath)
	} else {
		if pub, err = checkpoint.GenerateKey(abs); err != nil {
			return c.errorf("init: %v", err)
		}
		fmt.Fprintf(c.stdout, "generated key %s (mode 0600)\n", *keyPath)
	}
	pubPath := abs + ".pub"
	shownPub := *keyPath + ".pub"
	pem, _ := checkpoint.MarshalPublicKey(pub)
	if err := os.WriteFile(pubPath, pem, 0o644); err != nil {
		return c.errorf("init: %v", err)
	}
	id, err := tamperlog.Create(c.dir, pub, abs)
	if err != nil {
		return c.errorf("init: %v", err)
	}
	fmt.Fprintf(c.stdout, "initialized log %s in %s\npublic key: %s (copy it off this machine; verifiers need it)\n", hex.EncodeToString(id[:8]), c.dir, shownPub)
	return exitOK
}

// signer loads the private key from --key or meta.json. A missing key is not
// an error for append (no checkpoint is signed) but is for checkpoint.
func (c *cli) signer(keyFlag string) (ed25519.PrivateKey, error) {
	path := keyFlag
	if path == "" {
		m, _, err := tamperlog.ReadMeta(c.dir)
		if err != nil {
			return nil, err
		}
		path = m.KeyPath
	}
	if path == "" {
		return nil, nil
	}
	return checkpoint.LoadPrivateKey(path)
}

func (c *cli) cmdAppend(args []string) int {
	fs := c.flags("append")
	useStdin := fs.Bool("stdin", false, "read one entry per line from stdin")
	keyFlag := fs.String("key", "", "private key (default: path recorded at init)")
	batch := fs.Bool("batch", false, "fsync once per batch instead of per entry (see README risk note)")
	if fs.Parse(args) != nil {
		return exitErr
	}
	var payloads [][]byte
	for _, a := range fs.Args() {
		payloads = append(payloads, []byte(a))
	}
	if *useStdin {
		sc := bufio.NewScanner(c.stdin)
		sc.Buffer(make([]byte, 64<<10), entry.MaxPayload)
		for sc.Scan() {
			if len(sc.Bytes()) > 0 {
				payloads = append(payloads, append([]byte(nil), sc.Bytes()...))
			}
		}
		if err := sc.Err(); err != nil {
			return c.errorf("append: reading stdin: %v", err)
		}
	}
	if len(payloads) == 0 {
		return c.errorf("append: nothing to append (pass MESSAGE arguments or --stdin)")
	}
	priv, err := c.signer(*keyFlag)
	if err != nil {
		return c.errorf("append: %v", err)
	}
	opts := tamperlog.Options{Signer: priv, Logger: c.logger()}
	if *batch {
		opts.Sync, opts.BatchSize = tamperlog.SyncBatch, 1024
	}
	l, err := tamperlog.Open(c.dir, opts)
	if err != nil {
		return c.openErr(err)
	}
	defer l.Close()
	var first uint64
	for i := 0; i < len(payloads); i += 1000 {
		end := min(i+1000, len(payloads))
		s, err := l.AppendBatch(payloads[i:end])
		if err != nil {
			return c.errorf("append: %v", err)
		}
		if i == 0 {
			first = s
		}
	}
	msg := fmt.Sprintf("appended first=%d count=%d size=%d", first, len(payloads), l.Size())
	if priv != nil {
		cp, err := l.Checkpoint()
		if err != nil {
			return c.errorf("append: checkpoint: %v", err)
		}
		msg += fmt.Sprintf(" checkpoint=%d", cp.TreeSize)
	} else {
		fmt.Fprintln(c.stderr, "tamperlog: warning: no signing key; new entries are not covered by a checkpoint")
	}
	if err := l.Close(); err != nil {
		return c.errorf("append: %v", err)
	}
	fmt.Fprintln(c.stdout, msg)
	return exitOK
}

// pubkey loads --pubkey, or the log directory's pubkey.pem with a warning.
func (c *cli) pubkey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		fmt.Fprintf(c.stderr, "tamperlog: warning: no --pubkey; trusting %s from the log directory, which an attacker can replace\n", tamperlog.PubKeyFile)
		path = filepath.Join(c.dir, tamperlog.PubKeyFile)
	}
	return checkpoint.LoadPublicKey(path)
}

func (c *cli) cmdVerify(args []string) int {
	fs := c.flags("verify")
	pubPath := fs.String("pubkey", "", "public key obtained out of band")
	against := fs.String("against", "", "witness checkpoint file (detects rollback)")
	asJSON := fs.Bool("json", false, "print the full report as JSON")
	if fs.Parse(args) != nil {
		return exitErr
	}
	var opts tamperlog.VerifyOptions
	if *pubPath != "" {
		pub, err := checkpoint.LoadPublicKey(*pubPath)
		if err != nil {
			return c.errorf("verify: %v", err)
		}
		opts.PublicKey = pub
	}
	if *against != "" {
		w, err := checkpoint.ReadFile(*against)
		if err != nil {
			if errors.Is(err, checkpoint.ErrDecode) {
				return c.fail(&tamperlog.Finding{Reason: reason.CheckpointDecode, Seq: -1, Offset: -1, File: "witness", Detail: err.Error()})
			}
			return c.errorf("verify: %v", err)
		}
		opts.Witness = w
	}
	r, err := tamperlog.Verify(c.dir, opts)
	if err != nil {
		return c.errorf("verify: %v", err)
	}
	for _, w := range r.Warnings {
		fmt.Fprintln(c.stderr, "tamperlog: warning: "+w)
	}
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		enc.Encode(r)
	} else {
		fmt.Fprintln(c.stdout, r.String())
	}
	if !r.OK {
		return exitFail
	}
	return exitOK
}

func (c *cli) cmdCheckpoint(args []string) int {
	fs := c.flags("checkpoint")
	out := fs.String("o", "", "also write the checkpoint to FILE (give it to a witness)")
	keyFlag := fs.String("key", "", "private key (default: path recorded at init)")
	if fs.Parse(args) != nil {
		return exitErr
	}
	priv, err := c.signer(*keyFlag)
	if err != nil {
		return c.errorf("checkpoint: %v", err)
	}
	if priv == nil {
		return c.errorf("checkpoint: no signing key (pass --key)")
	}
	l, err := tamperlog.Open(c.dir, tamperlog.Options{Signer: priv, Logger: c.logger()})
	if err != nil {
		return c.openErr(err)
	}
	defer l.Close()
	cp, err := l.Checkpoint()
	if err != nil {
		return c.errorf("checkpoint: %v", err)
	}
	if *out != "" {
		b, _ := cp.MarshalBinary()
		if err := checkpoint.WriteFileAtomic(*out, b, 0o644); err != nil {
			return c.errorf("checkpoint: %v", err)
		}
	}
	fmt.Fprintf(c.stdout, "checkpoint size=%d root=%s time=%s\n", cp.TreeSize, cp.Root, cp.Time().Format(time.RFC3339Nano))
	return exitOK
}

func (c *cli) openRO() (*tamperlog.Log, int) {
	l, err := tamperlog.Open(c.dir, tamperlog.Options{ReadOnly: true})
	if err != nil {
		return nil, c.openErr(err)
	}
	return l, exitOK
}

func writeOut(path string, data []byte) error { return os.WriteFile(path, data, 0o644) }

func (c *cli) cmdProveInclusion(args []string) int {
	fs := c.flags("prove-inclusion")
	out := fs.String("o", "", "output file (default inclusion-SEQ-SIZE.proof)")
	if fs.Parse(args) != nil {
		return exitErr
	}
	if fs.NArg() != 1 {
		return c.errorf("prove-inclusion: need SEQ")
	}
	seq, err := strconv.ParseUint(fs.Arg(0), 10, 64)
	if err != nil {
		return c.errorf("prove-inclusion: bad SEQ %q", fs.Arg(0))
	}
	l, code := c.openRO()
	if l == nil {
		return code
	}
	defer l.Close()
	cp := l.LatestCheckpoint()
	if cp == nil || seq >= cp.TreeSize {
		return c.errorf("prove-inclusion: seq %d is not covered by a checkpoint yet; run `tamperlog checkpoint`", seq)
	}
	b, err := l.ProveInclusion(seq, cp)
	if err != nil {
		return c.errorf("prove-inclusion: %v", err)
	}
	data, _ := b.MarshalBinary()
	if *out == "" {
		*out = fmt.Sprintf("inclusion-%d-%d.proof", seq, cp.TreeSize)
	}
	if err := writeOut(*out, data); err != nil {
		return c.errorf("prove-inclusion: %v", err)
	}
	fmt.Fprintf(c.stdout, "proof seq=%d size=%d hashes=%d file=%s\n", seq, cp.TreeSize, len(b.Proof), *out)
	return exitOK
}

func (c *cli) cmdVerifyInclusion(args []string) int {
	fs := c.flags("verify-inclusion")
	pubPath := fs.String("pubkey", "", "public key obtained out of band")
	if fs.Parse(args) != nil {
		return exitErr
	}
	if fs.NArg() != 1 {
		return c.errorf("verify-inclusion: need PROOF file")
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return c.errorf("verify-inclusion: %v", err)
	}
	pub, err := c.pubkey(*pubPath)
	if err != nil {
		return c.errorf("verify-inclusion: %v", err)
	}
	b, err := tamperlog.DecodeInclusionBundle(data)
	if err != nil {
		return c.fail(&tamperlog.Finding{Reason: reason.ProofDecode, Seq: -1, Offset: -1, Detail: err.Error()})
	}
	e, f := b.Verify(pub)
	if f != nil {
		return c.fail(f)
	}
	fmt.Fprintf(c.stdout, "OK seq=%d size=%d root=%s time=%s payload=%s\n", e.Seq, b.Size, b.Checkpoint.Root, e.Time().Format(time.RFC3339Nano), strconv.Quote(string(e.Payload)))
	return exitOK
}

// resolveCheckpoint interprets OLD/NEW for prove-consistency.
func (c *cli) resolveCheckpoint(l *tamperlog.Log, arg string) (*checkpoint.Checkpoint, error) {
	if arg == "latest" {
		if cp := l.LatestCheckpoint(); cp != nil {
			return cp, nil
		}
		return nil, errors.New("no checkpoint yet")
	}
	if n, err := strconv.ParseUint(arg, 10, 64); err == nil {
		cp, err := checkpoint.ReadFile(filepath.Join(c.dir, tamperlog.CheckpointDir, fmt.Sprintf("%020d.ck", n)))
		if err != nil {
			return nil, fmt.Errorf("no local checkpoint for size %d", n)
		}
		return cp, nil
	}
	return checkpoint.ReadFile(arg)
}

func (c *cli) cmdProveConsistency(args []string) int {
	fs := c.flags("prove-consistency")
	out := fs.String("o", "", "output file (default consistency-OLD-NEW.proof)")
	if fs.Parse(args) != nil {
		return exitErr
	}
	if fs.NArg() != 2 {
		return c.errorf("prove-consistency: need OLD and NEW")
	}
	l, code := c.openRO()
	if l == nil {
		return code
	}
	defer l.Close()
	var cps [2]*checkpoint.Checkpoint
	for i := range cps {
		cp, err := c.resolveCheckpoint(l, fs.Arg(i))
		if err != nil {
			return c.errorf("prove-consistency: %s: %v", fs.Arg(i), err)
		}
		cps[i] = cp
	}
	b, err := l.ProveConsistency(cps[0], cps[1])
	if err != nil {
		var f *tamperlog.Finding
		if errors.As(err, &f) {
			return c.fail(f)
		}
		return c.errorf("prove-consistency: %v", err)
	}
	data, _ := b.MarshalBinary()
	if *out == "" {
		*out = fmt.Sprintf("consistency-%d-%d.proof", cps[0].TreeSize, cps[1].TreeSize)
	}
	if err := writeOut(*out, data); err != nil {
		return c.errorf("prove-consistency: %v", err)
	}
	fmt.Fprintf(c.stdout, "proof old=%d new=%d hashes=%d file=%s\n", cps[0].TreeSize, cps[1].TreeSize, len(b.Proof), *out)
	return exitOK
}

func (c *cli) cmdVerifyConsistency(args []string) int {
	fs := c.flags("verify-consistency")
	pubPath := fs.String("pubkey", "", "public key obtained out of band")
	if fs.Parse(args) != nil {
		return exitErr
	}
	if fs.NArg() != 1 {
		return c.errorf("verify-consistency: need PROOF file")
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return c.errorf("verify-consistency: %v", err)
	}
	pub, err := c.pubkey(*pubPath)
	if err != nil {
		return c.errorf("verify-consistency: %v", err)
	}
	b, err := tamperlog.DecodeConsistencyBundle(data)
	if err != nil {
		return c.fail(&tamperlog.Finding{Reason: reason.ProofDecode, Seq: -1, Offset: -1, Detail: err.Error()})
	}
	if f := b.Verify(pub); f != nil {
		return c.fail(f)
	}
	fmt.Fprintf(c.stdout, "OK old=%d new=%d old_root=%s new_root=%s\n", b.Old.TreeSize, b.New.TreeSize, b.Old.Root, b.New.Root)
	return exitOK
}

type jsonEntry struct {
	Seq         uint64  `json:"seq"`
	Timestamp   int64   `json:"timestamp_ns"`
	Time        string  `json:"time"`
	PrevHash    string  `json:"prev_hash"`
	Hash        string  `json:"hash"`
	Payload     string  `json:"payload_b64"`
	PayloadText *string `json:"payload_text,omitempty"`
}

type jsonCheckpoint struct {
	Size      uint64 `json:"size"`
	Root      string `json:"root"`
	Time      string `json:"time"`
	Signature string `json:"signature"`
}

func (c *cli) cmdExport(args []string) int {
	fs := c.flags("export")
	asJSON := fs.Bool("json", false, "JSON output (the only format)")
	if fs.Parse(args) != nil {
		return exitErr
	}
	if !*asJSON {
		return c.errorf("export: only --json is supported")
	}
	l, code := c.openRO()
	if l == nil {
		return code
	}
	defer l.Close()
	id := l.LogID()
	doc := struct {
		LogID      string          `json:"log_id"`
		Size       uint64          `json:"size"`
		Root       string          `json:"root"`
		Note       string          `json:"note"`
		Checkpoint *jsonCheckpoint `json:"latest_checkpoint,omitempty"`
		Entries    []jsonEntry     `json:"entries"`
	}{LogID: hex.EncodeToString(id[:]), Size: l.Size(), Root: l.Root().String(),
		Note: "JSON export is informational; integrity is defined by the binary segments and checkpoints"}
	if cp := l.LatestCheckpoint(); cp != nil {
		doc.Checkpoint = &jsonCheckpoint{Size: cp.TreeSize, Root: cp.Root.String(), Time: cp.Time().Format(time.RFC3339Nano), Signature: hex.EncodeToString(cp.Signature[:])}
	}
	doc.Entries = []jsonEntry{}
	for i := uint64(0); i < doc.Size; i++ {
		b, err := l.EntryBytes(i)
		if err != nil {
			return c.errorf("export: %v", err)
		}
		e, _ := entry.Unmarshal(b)
		je := jsonEntry{Seq: e.Seq, Timestamp: e.Timestamp, Time: e.Time().Format(time.RFC3339Nano),
			PrevHash: e.PrevHash.String(), Hash: entry.Hash(b).String(), Payload: base64.StdEncoding.EncodeToString(e.Payload)}
		if utf8.Valid(e.Payload) {
			s := string(e.Payload)
			je.PayloadText = &s
		}
		doc.Entries = append(doc.Entries, je)
	}
	enc := json.NewEncoder(c.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return c.errorf("export: %v", err)
	}
	return exitOK
}
