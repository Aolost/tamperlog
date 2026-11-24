package tamperlog

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/Aolost/tamperlog/checkpoint"
	"github.com/Aolost/tamperlog/merkle"
	"github.com/Aolost/tamperlog/reason"
	"github.com/Aolost/tamperlog/storage"
)

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// PublicKey verifies checkpoint signatures. If nil, dir/pubkey.pem is used
	// and a warning is added to the report: that file is under the
	// attacker's control.
	PublicKey ed25519.PublicKey
	// Witness is a checkpoint obtained out of band. It is the only defence
	// against rollback to an older valid state.
	Witness *checkpoint.Checkpoint
}

// Report is the result of Verify.
type Report struct {
	OK               bool        `json:"ok"`
	Failure          *Finding    `json:"failure,omitempty"`
	Size             uint64      `json:"size"`
	Root             merkle.Hash `json:"-"`
	RootHex          string      `json:"root"`
	Checkpoints      int         `json:"checkpoints"`
	LatestCheckpoint uint64      `json:"latest_checkpoint"`
	UnsignedTail     uint64      `json:"unsigned_tail"`
	WitnessChecked   bool        `json:"witness_checked"`
	Live             bool        `json:"live"`
	Warnings         []string    `json:"warnings,omitempty"`
}

// String renders the one-line machine-readable result.
func (r *Report) String() string {
	if !r.OK {
		return r.Failure.String()
	}
	w := ""
	if r.WitnessChecked {
		w = " witness=ok"
	}
	return fmt.Sprintf("OK size=%d root=%s checkpoint=%d unsigned_tail=%d%s", r.Size, r.Root, r.LatestCheckpoint, r.UnsignedTail, w)
}

func (r *Report) fail(f *Finding) *Report {
	r.OK = false
	r.Failure = f
	return r
}

// Verify checks the log in dir without trusting it. It returns an error only
// for I/O or usage problems; every integrity problem is a Report with
// OK=false and a Finding naming the reason and location.
func Verify(dir string, opts VerifyOptions) (*Report, error) {
	r := &Report{OK: true}
	_, logID, err := ReadMeta(dir)
	if err != nil {
		return nil, err
	}
	pub := opts.PublicKey
	if pub == nil {
		pub, err = checkpoint.LoadPublicKey(filepath.Join(dir, PubKeyFile))
		if err != nil {
			return nil, fmt.Errorf("tamperlog: no public key given and %s unreadable: %w", PubKeyFile, err)
		}
		r.Warnings = append(r.Warnings, "using "+PubKeyFile+" from the log directory; an attacker with write access can replace it. Pass the public key out of band.")
	}
	// Probe for a live writer. Holding a shared lock (when available) keeps a
	// writer from starting mid-verify.
	lk, err := storage.LockShared(dir)
	switch {
	case errors.Is(err, storage.ErrLocked):
		r.Live = true
	case err != nil:
		// Read-only copy (e.g. evidence on a read-only mount): there can be
		// no live writer, so verify strictly.
		r.Warnings = append(r.Warnings, "could not probe the writer lock ("+err.Error()+"); assuming no live writer")
	default:
		defer lk.Release()
	}

	// Checkpoints are read BEFORE segments: a writer always makes data
	// durable before the checkpoint that covers it.
	cps, err := readCheckpoints(dir)
	if err != nil {
		return nil, err
	}
	s, finding, err := scanEntries(dir, logID)
	if err != nil {
		return nil, err
	}
	if finding != nil {
		return r.fail(finding), nil
	}
	if t := s.res.Torn; t != nil {
		if r.Live {
			r.Warnings = append(r.Warnings, fmt.Sprintf("partial record at %s offset %d (append in progress)", t.Segment, t.Offset))
		} else {
			return r.fail(&Finding{Reason: reason.TornTail, Seq: int64(t.Index), Segment: t.Segment, Offset: t.Offset,
				Detail: fmt.Sprintf("%d trailing bytes are not a complete record", t.Bytes)}), nil
		}
	}
	n := s.tree.Size()
	r.Size, r.Root = n, s.tree.Root()
	r.RootHex = r.Root.String()

	// Local checkpoints, smallest first. lastGood is the largest size whose
	// signed root matched; it brackets where a divergence starts.
	var lastGood uint64
	for _, c := range cps {
		if c.err != nil {
			return r.fail(&Finding{Reason: reason.CheckpointDecode, Seq: -1, Offset: -1, File: c.name, Detail: c.err.Error()}), nil
		}
		if f := checkCheckpoint(c.cp, c.name, pub, logID, s.tree, lastGood, false); f != nil {
			return r.fail(f), nil
		}
		lastGood = c.cp.TreeSize
		r.Checkpoints++
	}
	r.LatestCheckpoint = lastGood

	if opts.Witness != nil {
		// lastGood for the witness is the largest verified local
		// checkpoint not beyond the witness.
		var below uint64
		for _, c := range cps {
			if c.cp.TreeSize <= opts.Witness.TreeSize {
				below = c.cp.TreeSize
			}
		}
		if f := checkCheckpoint(opts.Witness, "witness", pub, logID, s.tree, below, true); f != nil {
			return r.fail(f), nil
		}
		r.WitnessChecked = true
		if opts.Witness.TreeSize > lastGood {
			lastGood = opts.Witness.TreeSize
		}
	}
	r.UnsignedTail = n - lastGood
	if r.UnsignedTail > 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d entries after the newest checkpoint are protected only by the hash chain", r.UnsignedTail))
	}
	return r, nil
}

func checkCheckpoint(cp *checkpoint.Checkpoint, file string, pub ed25519.PublicKey, logID [32]byte, tree *merkle.Tree, lastGood uint64, witness bool) *Finding {
	f := &Finding{Seq: -1, Offset: -1, File: file}
	if err := cp.Verify(pub); err != nil {
		f.Reason, f.Detail = reason.CheckpointSignature, "signature does not verify under the given public key"
		return f
	}
	if cp.LogID != logID {
		f.Reason, f.Detail = reason.CheckpointLogID, "checkpoint was signed for a different log"
		return f
	}
	n := tree.Size()
	if cp.TreeSize > n {
		f.Seq = int64(n)
		if witness {
			f.Reason = reason.WitnessRollback
			f.Detail = fmt.Sprintf("witness checkpoint covers %d entries but the log has only %d: entries were removed or the log was rolled back", cp.TreeSize, n)
		} else {
			f.Reason = reason.LogTruncated
			f.Detail = fmt.Sprintf("checkpoint covers %d entries but the log has only %d", cp.TreeSize, n)
		}
		return f
	}
	root, _ := tree.RootAt(cp.TreeSize)
	if root != cp.Root {
		f.Seq = int64(lastGood)
		if witness {
			f.Reason = reason.WitnessRootMismatch
		} else {
			f.Reason = reason.CheckpointRootMismatch
		}
		f.Detail = fmt.Sprintf("signed root for size %d does not match; history diverges within seq [%d, %d)", cp.TreeSize, lastGood, cp.TreeSize)
		return f
	}
	return nil
}
