# tamperlog specification (format version 1)

tamperlog is a tamper-evident, append-only audit log. Any later edit, deletion,
reordering, or truncation is detectable by a verifier who does not trust the
machine that wrote the log. See [THREAT_MODEL.md](THREAT_MODEL.md) for the
attacker model and the limits, and [TESTPLAN.md](TESTPLAN.md) for how each
claim is tested.

All integers are big-endian. `H` is SHA-256. `||` is concatenation.

## 1. Entry

```
offset size field
0      1    version        = 0x01
1      8    seq            uint64, 0-based position in the log
9      8    timestamp      int64, Unix nanoseconds (UTC)
17     32   prev_hash      entry hash of entry seq-1, or the genesis hash for seq 0
49     4    payload_len    uint32, <= MaxPayload (16 MiB)
53     n    payload        opaque bytes
```

The encoding is canonical: a decoder rejects any other version, any length
other than exactly `53 + payload_len`, and any `payload_len` above the limit.
There is exactly one encoding of each entry. JSON is never hashed.

**Entry hash** = `H(0x00 || entry_bytes)`. It is also the Merkle leaf hash.

**Genesis hash** = `H("tamperlog/v1/genesis" || log_id)`, where `log_id` is 32
random bytes chosen at `init`. Binding entry 0 to the log ID means an entry
copied from another log breaks the chain even at seq 0.

**Writer rules**: `seq` is exactly the entry's position. `timestamp` is
`max(now, previous timestamp)`, so it never decreases.

## 2. Hash chain

`prev_hash` of entry `i` equals the entry hash of entry `i-1`. It gives cheap,
local, streaming tamper detection. It does not resist an attacker who rewrites
the chain from the edit point onward. That is what signed Merkle roots are for.

## 3. Merkle tree (RFC 6962 / RFC 9162 §2.1)

- `MTH({}) = H("")`
- `MTH({d0}) = H(0x00 || d0)` (the entry hash)
- `MTH(D[n]) = H(0x01 || MTH(D[0:k]) || MTH(D[k:n]))` where `k` is the largest
  power of two strictly smaller than `n`.

Inclusion proofs (`PATH`) and consistency proofs (`PROOF`/`SUBPROOF`) are exactly
RFC 9162 §2.1.3 and §2.1.4. The verifiers are the RFC 9162 §2.1.3.2 and
§2.1.4.2 algorithms. They need only the leaf hash or the proof, the root(s), and
the size(s). They reject trailing proof elements, indices `>= size`, and `m > n`.
The implementation is cross-checked against `golang.org/x/mod/sumdb/tlog` in
tests.

## 4. Signed checkpoint

```
offset size field
0      4    magic          "TLCK"
4      1    version        = 0x01
5      32   log_id
37     8    tree_size      uint64
45     32   root_hash      MTH of the first tree_size entries
77     8    timestamp      int64, Unix nanoseconds at signing
85     64   signature      Ed25519
```

The signature is over `"tamperlog checkpoint v1\n" || bytes[0:85]`. The
domain-separation prefix stops a checkpoint signature from being valid as any
other kind of message. The spec asks for (version, size, root, timestamp). The
log ID is added so a checkpoint cannot be replayed against a different log signed
by the same key.

Checkpoint files are written as: write `name.tmp`, fsync it, rename it to
`name`, then fsync the directory. Leftover `*.tmp` files are ignored and removed
on open.

## 5. Keys

- The private key is PKCS#8 PEM (`PRIVATE KEY`). The public key is PKIX PEM
  (`PUBLIC KEY`).
- Private key files are created with mode `0600` and `O_EXCL`.
- Loading a private key whose mode grants any permission to group or other
  (`mode & 0o077 != 0`) fails with `ErrKeyPermissions`. The mode is checked on
  the opened file descriptor, not on the path, so a swap between check and use
  is caught.
- Key material is never logged, printed, or put in error messages.

## 6. Storage

```
<dir>/
  meta.json                   log_id, format version, key path (no key material)
  pubkey.pem                  convenience copy. Do NOT trust it for verification.
  LOCK                        flock(2) target
  segments/<first-seq %020d>.seg
  checkpoints/<size %020d>.ck
```

A segment is a sequence of frames:

```
[length u32][crc32c u32][entry bytes (length)][entry hash (32)]
```

`crc32c` is CRC-32C (Castagnoli) over `length || entry bytes || entry hash`, so a
corrupted length prefix is caught whenever the frame is complete. A new segment
starts when the next frame would push the current one past `SegmentSize`
(default 64 MiB). After a new segment is created, the directory is fsynced.

**Concurrency**: one writer per directory, enforced by `flock(LOCK_EX|LOCK_NB)`
on `LOCK`, held for the life of the writer. Readers take no exclusive lock.
`verify` probes with `LOCK_SH|LOCK_NB`. If a writer holds the lock, the log is
*live*: a partial frame at the very end is treated as an append in progress,
not as damage. Within one process, `*Log` is safe for one writer goroutine and
many reader goroutines.

**fsync policy** (`SyncPolicy`):

- `SyncEvery` (default): fsync after every append. An acknowledged entry
  survives power loss.
- `SyncBatch`: fsync every `BatchSize` appends and on `Sync()`/`Close()`. Higher
  throughput, but up to `BatchSize-1` acknowledged entries can be lost on power
  failure. Recovery stays consistent because only a suffix is lost.
- `SyncNone`: never fsync explicitly (tests and benchmarks only).

A failed write poisons the writer. Every later call returns `ErrPoisoned`, and
the caller must reopen the log, which runs recovery.

## 7. Recovery on open

Open scans every segment in order and checks framing, CRC, entry decoding, stored
hash, seq, chain and timestamps.

- **Torn trailing record**: the last frame of the **last** segment is incomplete
  (fewer bytes than its header promises, or a partial header), or the tail is all
  zero bytes, **and** no valid frame starts anywhere after it. The file is
  truncated to the last good frame boundary and fsynced, a warning is logged, and
  open continues.
- **Mid-file corruption**: anything else (bad CRC on a complete frame, a bad
  length, an incomplete frame in a non-last segment, an incomplete frame followed
  by a valid frame, or any chain or seq error). Open refuses and returns a
  `*CorruptionError` with the reason code, segment and byte offset. The CLI
  exits non-zero.

A complete final frame with a bad CRC counts as corruption, not a torn write.
tamperlog never silently drops a frame that is fully present.

## 8. Verification

`verify` does not trust `meta.json`, `pubkey.pem`, or stored hashes. Order:

1. Read checkpoint files first, then segments. A concurrent writer always writes
   data before the checkpoint that covers it, so this order never produces a false
   `LOG_TRUNCATED`.
2. For each frame: framing, CRC, decode, stored hash = recomputed hash, seq,
   prev_hash, timestamp. The first failure stops the scan.
3. For each local checkpoint, in size order: decode, signature, log ID,
   `size <= log size`, root equals recomputed root at that size.
4. Witness (`--against`): signature, log ID, `size <= log size` (else
   `WITNESS_ROLLBACK`), root equals recomputed root at that size.

Output is one machine-readable line:

```
FAIL reason=<CODE> seq=<n|-> segment=<file|-> offset=<bytes|-> detail="..."
OK size=<n> root=<hex> checkpoint=<size> unsigned_tail=<n>
```

Exit status: `0` verified, `1` verification failure, `2` usage or I/O error.

### Reason codes

| Code | Meaning | Location reported |
| --- | --- | --- |
| `TORN_TAIL` | Incomplete final frame (not live) | seq, offset |
| `RECORD_TRUNCATED` | Incomplete frame that is not at the log's tail | seq, offset |
| `RECORD_LENGTH` | Length prefix out of range | seq, offset |
| `RECORD_CRC` | CRC-32C mismatch | seq, offset |
| `ENTRY_DECODE` | Entry bytes not canonical v1 | seq, offset |
| `ENTRY_HASH_MISMATCH` | Stored entry hash differs from the recomputed one | seq, offset |
| `SEQ_GAP` | Expected seq missing from the log | seq (expected), offset |
| `SEQ_DUPLICATE` | Seq already seen | seq, offset |
| `SEQ_ORDER` | Entries out of order | seq (expected), offset |
| `CHAIN_BREAK` | `prev_hash` does not match the previous entry hash | seq, offset |
| `TIMESTAMP_REGRESSION` | Timestamp earlier than the previous entry | seq, offset |
| `CHECKPOINT_DECODE` | Malformed checkpoint file | file |
| `CHECKPOINT_SIGNATURE` | Ed25519 verification failed | file |
| `CHECKPOINT_LOG_ID` | Checkpoint belongs to a different log | file |
| `CHECKPOINT_ROOT_MISMATCH` | Signed root differs from the recomputed root | first seq of the first diverging range |
| `LOG_TRUNCATED` | A local checkpoint covers entries that are missing | first missing seq |
| `WITNESS_ROLLBACK` | Witness checkpoint is larger than the log | first missing seq |
| `WITNESS_ROOT_MISMATCH` | Witness root differs from the recomputed root | first seq after the newest matching local checkpoint |
| `PROOF_DECODE` | Malformed proof bundle | - |
| `PROOF_INVALID` | Proof does not verify | - |

## 9. Proof bundles

Inclusion (`prove-inclusion` → `verify-inclusion`):

```
"TLIP" | 0x01 | u32 len | checkpoint | u32 len | entry bytes | u64 index | u64 size | u8 count | count × 32-byte hash
```

Consistency (`prove-consistency` → `verify-consistency`):

```
"TLCS" | 0x01 | u32 len | old checkpoint | u32 len | new checkpoint | u8 count | count × 32-byte hash
```

Decoders are strict: there must be no trailing bytes, `count <= 64`, and the
embedded lengths must match. A bundle verifies only if the checkpoint signatures
are valid, the indices and sizes agree with the embedded checkpoints and entry,
and the Merkle proof verifies.

## 10. CLI

```
tamperlog [--dir DIR] init --key PATH
tamperlog [--dir DIR] append [--stdin] [MESSAGE...]
tamperlog [--dir DIR] verify [--pubkey P] [--against CHECKPOINT] [--json]
tamperlog [--dir DIR] checkpoint [-o FILE]
tamperlog [--dir DIR] prove-inclusion SEQ [-o FILE]
tamperlog verify-inclusion PROOF --pubkey P
tamperlog [--dir DIR] prove-consistency OLD NEW [-o FILE]
tamperlog verify-consistency PROOF --pubkey P
tamperlog [--dir DIR] export --json
```

`DIR` defaults to `$TAMPERLOG_DIR`, then `./.tamperlog`. `OLD` and `NEW` are
either a tree size that has a local checkpoint, `latest`, or the path to a
checkpoint file (for example one a witness holds).
