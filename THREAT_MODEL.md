# tamperlog threat model

## Assets

- **Integrity of log history**: the exact bytes of every entry (sequence number,
  timestamp, payload, chain link).
- **Ordering of log history**: the position of every entry relative to every
  other entry.
- **Completeness up to a signed point**: no entry covered by a signed checkpoint
  may disappear without detection.

Confidentiality is **not** an asset. Payloads are stored in clear text.
Availability is **not** an asset: an attacker who can write the files can
always delete them. tamperlog makes the deletion detectable, not impossible.

## Actors

| Actor | Trust | Holds |
| --- | --- | --- |
| Writer | Trusted at write time | Ed25519 private key, write access to the log directory |
| Attacker | Untrusted | Read and write access to the log directory **after** entries were written |
| Verifier | Trusted, but does not trust the machine that holds the log | Public key (obtained out of band); ideally a recent checkpoint from a witness |
| Witness | Trusted to keep what it was given | Copies of signed checkpoints, stored off the writer's machine |

## Attacker capabilities

The attacker can do any of the following to the files in the log directory, in any
combination, and can recompute any non-keyed value (CRC32C, SHA-256 entry
hashes, hash chain links, Merkle roots) after doing it:

1. Edit any byte of any entry (sequence number, timestamp, payload, prev_hash,
   stored entry hash, CRC, length prefix).
2. Delete an entry in the middle or at the end.
3. Duplicate an entry.
4. Reorder (swap) entries.
5. Truncate the log, including to an exact record boundary (a "valid shorter
   prefix").
6. Splice in an entry or a segment copied from a different tamperlog log.
7. Replace the whole directory with an older, fully valid copy of itself
   (rollback), including the older checkpoints and the older public key file.
8. Delete, replace, or forge checkpoint files.
9. Replace `pubkey.pem` and `meta.json` in the log directory.

The attacker **cannot** forge an Ed25519 signature without the private key.

## What tamperlog detects

| Attack | Detected by | Reason code |
| --- | --- | --- |
| Bit flip anywhere in a record, CRC not fixed | CRC32C over the frame | `RECORD_CRC` / `RECORD_LENGTH` |
| Field edit with CRC fixed, stored hash not fixed | Recomputed entry hash | `ENTRY_HASH_MISMATCH` |
| Field edit with CRC and stored hash fixed | Next entry's `prev_hash` or the signed root | `CHAIN_BREAK` / `SEQ_*` / `TIMESTAMP_REGRESSION` / `CHECKPOINT_ROOT_MISMATCH` |
| Edit with the whole chain after it recomputed | Signed Merkle root of any checkpoint that covers it | `CHECKPOINT_ROOT_MISMATCH` |
| Delete middle entry | Sequence numbers | `SEQ_GAP` |
| Duplicate entry | Sequence numbers | `SEQ_DUPLICATE` |
| Swap entries | Sequence numbers | `SEQ_ORDER` |
| Splice entry from another log | Hash chain (genesis is bound to the log ID) | `CHAIN_BREAK` |
| Timestamp moved backwards | Monotonic timestamp check | `TIMESTAMP_REGRESSION` |
| Delete last entry, local checkpoints intact | Checkpoint size larger than log | `LOG_TRUNCATED` |
| Delete last entry and the newest checkpoints, or roll back to an older valid copy | **Only** a newer checkpoint held by the verifier (`--against`) | `WITNESS_ROLLBACK` |
| History rewritten after the witness checkpoint was taken | Witness root against recomputed root | `WITNESS_ROOT_MISMATCH` |
| Forged or altered checkpoint | Ed25519 signature | `CHECKPOINT_SIGNATURE` |
| Checkpoint from a different log | Log ID inside the signed checkpoint | `CHECKPOINT_LOG_ID` |
| Partially written trailing record | Frame framing | `TORN_TAIL` |

## What tamperlog does NOT protect against (limits, stated plainly)

1. **Rollback without a witness is undetectable.** An attacker who replaces the
   directory with an older valid copy (entries, checkpoints, key file and all)
   produces a log that is internally perfect. Only a verifier that holds a
   checkpoint newer than that copy, obtained out of band, can detect it. If you
   do not ship checkpoints to a witness, you have no rollback protection.

2. **A compromised signing key at write time is out of scope.** Anyone with the
   private key can sign any history, including a rewritten one. tamperlog does
   not detect this. Keep the key off the log host if you can, and rotate it if
   the host is compromised. Checkpoints that a witness already holds still pin
   the history up to their size, because a rewritten history will not match
   those roots.

3. **Unsigned tail.** Entries appended after the newest checkpoint are protected
   only by the hash chain, which an attacker can recompute. They can be
   rewritten or dropped without detection until a checkpoint covers them. The
   CLI signs a checkpoint after every `append` by default to keep this window
   small; library users choose `CheckpointEvery`. `verify` reports the size of
   the unsigned tail.

4. **Trusting the public key in the log directory.** `pubkey.pem` lives next to
   the data and can be replaced along with everything else. `verify` uses it only
   when `--pubkey` is not given, and then prints a warning. Real verification
   must use a public key obtained out of band.

5. **Lies at write time.** A compromised writer can log false payloads,
   wrong timestamps (within the monotonic rule), or simply stop logging.
   tamperlog proves that history was not changed after it was written, not that
   it was true when written.

6. **Deletion of the whole log** is not prevented. It is detectable only by a
   witness that expects the log to exist.

7. **Confidentiality.** Payloads are not encrypted. Do not log secrets.

8. **Batched fsync.** With `SyncBatch`, an acknowledged append can be lost in a
   power failure. Recovery trims the torn tail so the log stays consistent, but
   up to `BatchSize-1` acknowledged entries may be gone. If a checkpoint was
   signed over entries that were then lost, `verify` reports `LOG_TRUNCATED`,
   which is the correct answer: entries the log once claimed are gone.

9. **Denial of service by corruption.** An attacker can make the log refuse to
   open by corrupting the middle of a segment. This is intentional: tamperlog
   refuses to append to a log whose history it cannot vouch for.

## Out of scope

- Side channels and timing attacks on the verifier.
- Multi-writer logs. One writer per directory is enforced by `flock(2)`. The
  lock is advisory and protects against accidents, not against an attacker.
- Non-Unix platforms. Locking uses `flock(2)`.
