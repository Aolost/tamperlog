# tamperlog test plan

Written before the implementation. Each line names the test that implements it.

## 1. Tamper simulation matrix (`tamper_test.go`)

Setup: a log with 8 entries. A checkpoint is signed after every append, so local
checkpoints exist at sizes 1..8. The witness is a copy of the size-8 checkpoint
kept outside the directory.

There are three attacker strengths for field edits:

- **raw**: flip a bit, fix nothing.
- **crc**: flip a bit, recompute CRC-32C.
- **full**: flip a bit, recompute the stored entry hash and CRC-32C.

| Case | Expected reason | Expected location |
| --- | --- | --- |
| raw bit flip in each field (length, crc, version, seq, timestamp, prev_hash, payload_len, payload, stored hash) of a middle entry | `RECORD_CRC` or `RECORD_LENGTH` (length field) | that entry's seq and frame offset |
| crc flip in version / payload_len | `ENTRY_DECODE` | that seq |
| crc flip in seq, timestamp, prev_hash, payload, stored hash | `ENTRY_HASH_MISMATCH` | that seq |
| full flip in seq | `SEQ_GAP` / `SEQ_ORDER` / `SEQ_DUPLICATE` (by direction) | that seq |
| full flip in prev_hash | `CHAIN_BREAK` | that seq |
| full flip in timestamp (low bit, forward) | `CHAIN_BREAK` | seq+1 |
| full flip in payload of a middle entry | `CHAIN_BREAK` | seq+1 |
| full flip in payload of the **last** entry | `CHECKPOINT_ROOT_MISMATCH` | last seq |
| full rewrite of a middle entry and the whole chain after it | `CHECKPOINT_ROOT_MISMATCH` | that seq |
| delete middle entry | `SEQ_GAP` | deleted seq |
| delete last entry, local checkpoints intact | `LOG_TRUNCATED` | last seq |
| delete last entry and newest checkpoint, with witness | `WITNESS_ROLLBACK` | last seq |
| delete last entry and newest checkpoint, no witness | **accepted** (documented limit, asserted) | - |
| swap two entries | `SEQ_ORDER` | first swapped seq |
| duplicate an entry | `SEQ_DUPLICATE` | duplicated position |
| replace directory with valid shorter copy, with newer witness | `WITNESS_ROLLBACK` | first missing seq |
| same, without witness | **accepted** (documented limit, asserted) | - |
| splice same-seq entry from another log | `CHAIN_BREAK` | that seq |
| splice entry 0 from another log | `CHAIN_BREAK` | 0 |
| timestamp goes backwards (full) | `TIMESTAMP_REGRESSION` | that seq |
| corrupt CRC field | `RECORD_CRC` | that seq, offset |
| forge checkpoint signature (flip signature byte) | `CHECKPOINT_SIGNATURE` | file |
| alter signed checkpoint body (size/root) | `CHECKPOINT_SIGNATURE` | file |
| checkpoint signed by another key | `CHECKPOINT_SIGNATURE` | file |
| forged witness | `CHECKPOINT_SIGNATURE` | witness |
| witness from another log | `CHECKPOINT_LOG_ID` | witness |
| rewritten history, witness of original | `WITNESS_ROOT_MISMATCH` | - |
| `pubkey.pem` replaced and log re-signed, verified with real `--pubkey` | `CHECKPOINT_SIGNATURE` | file |

The test also asserts that the untouched log verifies, so that every failure
above comes from the tamper and not from the setup.

## 2. Merkle properties (`merkle/*_test.go`)

- For every n in 1..2000 and every index < n, the inclusion proof verifies against
  `Root(n)`.
- For every 1 <= m < n <= 300, the consistency proof verifies. m == n with an
  empty proof verifies.
- Mutation: for a sample of (index, n) and (m, n), every single-byte mutation
  (XOR 0x01 and XOR 0xFF at each byte) of each proof hash and of the root makes
  verification fail. Wrong index, wrong size, truncated and extended proofs fail.
- Cross-check against `golang.org/x/mod/sumdb/tlog`: roots for n in 1..1024
  (and some larger), inclusion and consistency proofs byte-identical, and each
  implementation's proofs verify under the other's verifier.

## 3. Encoding (`entry/*_test.go`, `checkpoint/*_test.go`)

- Round trip. Golden vector for the v1 encoding, so an accidental format change
  breaks the test. Non-canonical inputs (wrong version, trailing bytes, short
  buffer, oversize length) are rejected.
- Key files: refuse 0640/0644/0604, accept 0600/0400, `O_EXCL` on generate, no
  key bytes in any error string.

## 4. Crash tests (`storage/crash_test.go`, `crash_test.go`)

- A `WriteFile` wrapper cuts the write at every byte offset `0..len(frame)` of
  the next record, then fails. Reopen. Size must be exactly the previous size
  (cut < len) or the previous size + 1 (cut == len). All earlier entries must be
  byte-identical, the chain must verify, and the next append must work.
- The writer is poisoned after a failed write.
- Torn header, torn body, zero-filled tail: truncated, warning logged.
- Bad CRC mid-file, bad CRC on the complete final frame, incomplete frame in a
  non-last segment, incomplete frame followed by a valid frame: open refuses with
  `*CorruptionError` naming the offset.
- Leftover `*.tmp` checkpoint is ignored and removed.
- Segment rollover across many small segments, then reopen.

## 5. Concurrency (`concurrency_test.go`, run under `-race`)

- One writer goroutine appending, N reader goroutines calling `Entry`, `Root`,
  `InclusionProof`, `ConsistencyProof` and verifying the results.
- `Verify(dir)` from a reader while the writer appends (live mode) never reports
  a false failure.
- A second writer `Open` on the same directory fails with `ErrLocked`.

## 6. Fuzzing

- `FuzzDecodeEntry`, `FuzzParseFrame`, `FuzzDecodeCheckpoint`,
  `FuzzDecodeInclusionBundle`, `FuzzDecodeConsistencyBundle`. Invariants: no
  panic, and when decoding succeeds, re-encoding gives the same bytes
  (canonicality).
- The interesting corpus is committed under `testdata/fuzz/`.

## 7. CLI (`cmd/tamperlog/main_test.go`)

- Every subcommand runs end to end in-process. Every failure path prints
  `reason=` and exits with the documented status.

## 8. Benchmarks (`make bench`)

- Append throughput: `SyncEvery` vs `SyncBatch(64)` vs `SyncNone`.
- Inclusion proof size and verify time for n = 1e3, 1e4, 1e5, 1e6.
- The measured table goes into the README.

## Acceptance

`make check` = `go vet` + `go test -race` + total coverage of at least 85%.
