// Package reason defines the machine-readable reason codes reported by every
// tamperlog verification failure. The string values are a stable interface:
// scripts match on them.
package reason

// Code is a machine-readable failure reason.
type Code string

// Reason codes. See SPEC.md §8.
const (
	OK                     Code = "OK"
	TornTail               Code = "TORN_TAIL"
	RecordTruncated        Code = "RECORD_TRUNCATED"
	RecordLength           Code = "RECORD_LENGTH"
	RecordCRC              Code = "RECORD_CRC"
	EntryDecode            Code = "ENTRY_DECODE"
	EntryHashMismatch      Code = "ENTRY_HASH_MISMATCH"
	SeqGap                 Code = "SEQ_GAP"
	SeqDuplicate           Code = "SEQ_DUPLICATE"
	SeqOrder               Code = "SEQ_ORDER"
	ChainBreak             Code = "CHAIN_BREAK"
	TimestampRegression    Code = "TIMESTAMP_REGRESSION"
	CheckpointDecode       Code = "CHECKPOINT_DECODE"
	CheckpointSignature    Code = "CHECKPOINT_SIGNATURE"
	CheckpointLogID        Code = "CHECKPOINT_LOG_ID"
	CheckpointRootMismatch Code = "CHECKPOINT_ROOT_MISMATCH"
	LogTruncated           Code = "LOG_TRUNCATED"
	WitnessRollback        Code = "WITNESS_ROLLBACK"
	WitnessRootMismatch    Code = "WITNESS_ROOT_MISMATCH"
	ProofDecode            Code = "PROOF_DECODE"
	ProofInvalid           Code = "PROOF_INVALID"
	IOError                Code = "IO_ERROR"
)
