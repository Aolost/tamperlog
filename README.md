# tamperlog

A tamper-evident, append-only audit log in Go (1.22+).

Any later **edit, deletion, reordering, or truncation** of the log is detectable
by a verifier who does not trust the machine that wrote it. tamperlog combines
three layers:

| Layer | What it gives you |
| --- | --- |
| **Hash chain**: each entry carries the hash of the previous one | Cheap, streaming, local tamper detection |
| **RFC 6962 / RFC 9162 Merkle tree** | Compact inclusion and consistency proofs (about 640 bytes at 1M entries) |
| **Ed25519-signed checkpoints** | An attacker who rewrites the chain still cannot produce a matching signed root |

It is a library first (`github.com/Aolost/tamperlog`) with a small CLI on top.

- [SPEC.md](SPEC.md): byte-level formats, recovery rules, reason codes
- [THREAT_MODEL.md](THREAT_MODEL.md): attacker model and limits
- [TESTPLAN.md](TESTPLAN.md): how every claim is tested

## What it does NOT protect against

Read this before relying on it.

1. **Rollback without a witness is undetectable.** If an attacker replaces the
   whole log directory with an older, valid copy (entries, checkpoints and all),
   the log is internally perfect. Only a verifier that holds a **newer
   checkpoint obtained out of band** (`verify --against`) can detect it. If you
   never ship checkpoints off the machine, you have no rollback protection.
2. **A compromised signing key at write time is out of scope.** Whoever holds
   the private key can sign any history. Checkpoints a witness already holds
   still pin history up to their size.
3. **The unsigned tail.** Entries appended after the newest checkpoint are
   protected only by the hash chain, which an attacker can recompute. The CLI
   signs after every `append` to keep this window at zero. `verify` reports it
   as `unsigned_tail=N`.
4. **`pubkey.pem` in the log directory is not a trust anchor.** An attacker can
   replace it. Always verify with `--pubkey` from a copy you keep elsewhere.
5. **Lies at write time.** tamperlog proves history was not changed after it was
   written, not that it was true when written.
6. **Deleting everything** is not prevented, only made noticeable to a witness
   that expects the log to exist. Payloads are **not encrypted**.
7. **Batched fsync** (`SyncBatch`, `append --batch`) can lose up to
   `BatchSize-1` acknowledged entries on power loss. Recovery stays consistent.
   A checkpoint always fsyncs first, so it never covers data that was lost.

## Demo: tampering and detection

`make demo` runs [scripts/demo.sh](scripts/demo.sh). Real output:

```
$ tamperlog init --key signing.pem
generated key signing.pem (mode 0600)
initialized log 528ea954e72ffee1 in audit
public key: signing.pem.pub (copy it off this machine; verifiers need it)
[exit 0]

$ tamperlog append "user=alice action=login"
appended first=0 count=1 size=1 checkpoint=1
[exit 0]

$ tamperlog append "user=alice action=sudo"
appended first=1 count=1 size=2 checkpoint=2
[exit 0]

$ tamperlog append "user=bob action=delete-db"
appended first=2 count=1 size=3 checkpoint=3
[exit 0]

$ tamperlog checkpoint -o witness.ck
checkpoint size=3 root=140ff8b1a42614057f0f905048ae1b8401993b6efaf1d9b113b3ddcf6c84d452 time=2026-11-24T21:48:21.718674682Z
[exit 0]

$ tamperlog verify --pubkey signing.pem.pub --against witness.ck
OK size=3 root=140ff8b1a42614057f0f905048ae1b8401993b6efaf1d9b113b3ddcf6c84d452 checkpoint=3 unsigned_tail=0 witness=ok
[exit 0]

# 1. attacker flips one byte in the middle of the log
$ printf X | dd of=audit/segments/00000000000000000000.seg bs=1 seek=180 conv=notrunc
$ tamperlog verify --pubkey signing.pem.pub
FAIL reason=RECORD_CRC seq=1 segment=00000000000000000000.seg offset=116 detail="crc32c mismatch"
[exit 1]

# 2. attacker deletes the last entry, cutting at an exact record boundary
$ truncate -s -118 audit/segments/00000000000000000000.seg
$ tamperlog verify --pubkey signing.pem.pub
FAIL reason=LOG_TRUNCATED seq=2 segment=- offset=- file=00000000000000000003.ck detail="checkpoint covers 3 entries but the log has only 2"
[exit 1]

# 3. ...and also deletes the newest checkpoint. Locally the log now looks
#    perfect; only the witness checkpoint held elsewhere catches it.
$ rm audit/checkpoints/00000000000000000003.ck
$ tamperlog verify --pubkey signing.pem.pub
OK size=2 root=95012063522ba8fd24f61cd2ccb05ceedede291a1f6178c7bab3e1547a5ffcf1 checkpoint=2 unsigned_tail=0
[exit 0]

$ tamperlog verify --pubkey signing.pem.pub --against witness.ck
FAIL reason=WITNESS_ROLLBACK seq=2 segment=- offset=- file=witness detail="witness checkpoint covers 3 entries but the log has only 2: entries were removed or the log was rolled back"
[exit 1]
```

## Install and CLI

```bash
make build            # bin/tamperlog
```

```
tamperlog [--dir DIR] init --key PATH
tamperlog [--dir DIR] append [--stdin] [--batch] [MESSAGE...]
tamperlog [--dir DIR] verify [--pubkey P] [--against CHECKPOINT] [--json]
tamperlog [--dir DIR] checkpoint [-o FILE]
tamperlog [--dir DIR] prove-inclusion SEQ [-o FILE]
tamperlog verify-inclusion PROOF --pubkey P
tamperlog [--dir DIR] prove-consistency OLD NEW [-o FILE]
tamperlog verify-consistency PROOF --pubkey P
tamperlog [--dir DIR] export --json
```

`DIR` defaults to `$TAMPERLOG_DIR`, then `./.tamperlog`. Exit status: `0`
verified, `1` integrity failure, `2` usage or I/O error. Every failure prints
one machine-readable line:

```
FAIL reason=<CODE> seq=<first bad seq> segment=<file> offset=<byte> [file=<checkpoint>] detail="..."
```

The reason codes (`RECORD_CRC`, `CHAIN_BREAK`, `SEQ_GAP`, `LOG_TRUNCATED`,
`WITNESS_ROLLBACK`, ...) are listed in [SPEC.md §8](SPEC.md#reason-codes).

### Witness workflow

```bash
tamperlog checkpoint -o /tmp/cp.ck && scp /tmp/cp.ck witness:/var/witness/
# later, on any machine with the public key and the witness copy:
tamperlog --dir ./copy-of-log verify --pubkey signing.pem.pub --against cp.ck
# prove the log only grew since the witness's checkpoint:
tamperlog prove-consistency cp.ck latest -o grow.proof
tamperlog verify-consistency grow.proof --pubkey signing.pem.pub
```

## Library use

```go
priv, err := checkpoint.LoadPrivateKey("/etc/secsuite/audit.pem") // refuses mode != 0600/0400
if _, err := os.Stat(dir + "/meta.json"); os.IsNotExist(err) {
	tamperlog.Create(dir, priv.Public().(ed25519.PublicKey), "")
}
l, err := tamperlog.Open(dir, tamperlog.Options{
	Signer:          priv,
	Sync:            tamperlog.SyncEvery, // or SyncBatch + BatchSize
	CheckpointEvery: 1,                   // sign after every append
})
if err != nil {
	var ce *tamperlog.CorruptionError // mid-file corruption: refuse to continue
	...
}
defer l.Close()
seq, err := l.Append([]byte(`{"user":"alice","action":"login"}`))

// Anywhere else, without trusting the writer's machine:
rep, err := tamperlog.Verify(dir, tamperlog.VerifyOptions{PublicKey: pub, Witness: cp})
if !rep.OK { log.Print(rep.Failure) } // FAIL reason=... seq=... offset=...
```

`*Log` is safe for one appending goroutine and any number of reader goroutines
(`Entry`, `RootAt`, `InclusionProof`, `ConsistencyProof`). A second writer on
the same directory gets `ErrLocked` (flock). `Verify` and
`Open(dir, Options{ReadOnly: true})` run alongside a live writer.

## How it works

- **Entry** (v1, canonical, length-prefixed, never JSON):
  `version | seq u64 | timestamp i64 | prev_hash[32] | payload_len u32 | payload`.
  The entry hash is `SHA-256(0x00 || entry)`, which is also the Merkle leaf. Entry 0's
  `prev_hash` is bound to a random log ID, so entries cannot be spliced between
  logs.
- **Merkle tree**: RFC 9162 §2.1 exactly. The tree stores every complete subtree,
  so roots and proofs for any past size cost O(log n). Verifiers are the RFC 9162
  §2.1.3.2 and §2.1.4.2 algorithms. Tests cross-check roots and proofs byte for
  byte against `golang.org/x/mod/sumdb/tlog`.
- **Checkpoints**: Ed25519 over a domain-separated
  `(version, log_id, size, root, timestamp)`. Files are written temp → fsync →
  rename → fsync dir. Private keys must be `0600` or stricter, checked on the open
  file descriptor. Key bytes never appear in logs or errors.
- **Storage**: segment files of `[len u32][crc32c][entry][entry hash]`. On open,
  a **torn trailing record** (incomplete frame or zero fill at the very end, with
  no valid frame after it) is truncated with a warning. **Anything else** (bad CRC
  on a complete frame, a hole, a chain break) makes `Open` refuse with a
  `*CorruptionError` naming the reason and byte offset.

One subtlety the property tests surfaced: an RFC 9162 inclusion proof does not
authenticate the tree *size* by itself. The proof for (index 5, size 7) also
recomputes the same root when you claim size 8. The size is authenticated only
by the signed checkpoint that pairs it with the root, so proof bundles require
`size == checkpoint.size`, and the bundle-level mutation test covers this.

## Testing

```bash
make check    # gofmt, go vet, go test -race on everything, coverage >= 85%
make fuzz     # 5 fuzz targets (FUZZTIME=30s each by default)
make bench    # benchmarks, run on a disk-backed temp dir
```

- **Tamper matrix** ([tamper_test.go](tamper_test.go)): every field of an
  entry bit-flipped at three attacker strengths (raw, CRC recomputed, CRC and
  hash recomputed), delete middle/last, swap, duplicate, rollback to a valid
  prefix, splice from another log (including at seq 0), timestamp regression,
  corrupt CRC, forged, altered and foreign-key checkpoints, and a replaced
  `pubkey.pem`. Each case asserts the reason code and location. The two
  documented limits (rollback and deleted-checkpoint truncation without a
  witness) are asserted as *accepted*, so a behaviour change is noticed.
- **Properties** ([merkle/merkle_test.go](merkle/merkle_test.go)): every
  inclusion proof for every n ≤ 2000, every consistency proof for
  1 ≤ m < n ≤ 300, and single-byte mutations of proofs, roots and encoded
  bundles all rejected.
- **Crash** ([crash_test.go](crash_test.go)): the next record is cut at every
  byte offset. After reopening, the log is at exactly the previous record or the
  new one, earlier entries are byte-identical, and the writer is poisoned after a
  failed write or fsync.
- **Concurrency**: one writer, four proof-checking readers and a live `Verify`
  loop, under `-race`.
- **Fuzzing**: entry, frame, checkpoint and both proof-bundle decoders. Each
  must not panic and must be canonical (decode then encode gives the same bytes).
  The corpus is committed under `*/testdata/fuzz/`.

## Benchmarks

Measured with `make bench` on an AMD Ryzen 5 5500U, Linux, **btrfs on
dm-crypt (NVMe)**, Go 1.24, 128-byte payloads. Your disk dominates the fsync
rows. (On tmpfs, fsync is a no-op and the first row would be meaningless, so
`make bench` runs in a disk-backed directory.)

**Append throughput**

| fsync policy | time / append | appends / s | durability |
| --- | ---: | ---: | --- |
| `SyncEvery` (default) | 1.75 ms | ~570 | every acknowledged entry survives power loss |
| `SyncBatch`, BatchSize 64 | 48.5 µs | ~20,600 | up to 63 acknowledged entries can be lost |
| `SyncNone` (tests only) | 14.2 µs | ~70,500 | none beyond the OS page cache |

**Proof size and verify time vs. tree size n** (inclusion at index n/3,
consistency from m = n/2 + 7)

| n | inclusion proof | inclusion verify | inclusion prove | consistency proof | consistency verify |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 320 B | 2.6 µs | 2.0 µs | 352 B | 4.8 µs |
| 10,000 | 448 B | 3.7 µs | 2.2 µs | 480 B | 5.5 µs |
| 100,000 | 544 B | 4.4 µs | 2.3 µs | 576 B | 6.5 µs |
| 1,000,000 | 640 B | 5.5 µs | 3.9 µs | 672 B | 7.6 µs |

Proofs grow with log2(n): 32 bytes per tree level. Building the in-memory tree
costs about 64 bytes per entry (leaf hashes plus complete-subtree hashes).

## Licence

[MIT](LICENSE) © 2026 Skepta.
