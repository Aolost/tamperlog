//go:build unix

package storage

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// LockFile is the name of the lock file inside a log directory.
const LockFile = "LOCK"

// ErrLocked is returned when another writer holds the directory lock.
var ErrLocked = errors.New("storage: log is locked by another writer")

// Lock is a held flock(2) on dir/LOCK.
type Lock struct{ f *os.File }

func flock(dir string, how int) (*Lock, error) {
	f, err := os.OpenFile(filepath.Join(dir, LockFile), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return &Lock{f: f}, nil
}

// LockExclusive takes the single-writer lock without blocking.
func LockExclusive(dir string) (*Lock, error) { return flock(dir, syscall.LOCK_EX) }

// LockShared takes a shared (reader) lock without blocking. It fails with
// ErrLocked while a writer holds the exclusive lock.
func LockShared(dir string) (*Lock, error) { return flock(dir, syscall.LOCK_SH) }

// Release drops the lock.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close() // closing the descriptor releases the flock
	l.f = nil
	return err
}
