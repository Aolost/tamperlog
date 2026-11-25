//go:build windows

package storage

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// LockFile is the name of the lock file inside a log directory.
const LockFile = "LOCK"

// ErrLocked is returned when another writer holds the directory lock.
var ErrLocked = errors.New("storage: log is locked by another writer")

// Lock is a held LockFileEx byte-range lock on dir/LOCK. It has the same
// semantics as the Unix flock: one exclusive writer, or many shared readers,
// never blocking, released when the handle is closed.
type Lock struct{ f *os.File }

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2
	errorLockViolation      = syscall.Errno(33)
	errorIOPending          = syscall.Errno(997)
)

var (
	modkernel32    = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx = modkernel32.NewProc("LockFileEx")
)

func lockFileEx(dir string, flags uint32) (*Lock, error) {
	f, err := os.OpenFile(filepath.Join(dir, LockFile), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	var ol syscall.Overlapped
	// Lock one byte at offset 0; the file content is irrelevant.
	r, _, e := procLockFileEx.Call(f.Fd(), uintptr(flags|lockfileFailImmediately), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r == 0 {
		f.Close()
		if e == errorLockViolation || e == errorIOPending {
			return nil, ErrLocked
		}
		return nil, e
	}
	return &Lock{f: f}, nil
}

// LockExclusive takes the single-writer lock without blocking.
func LockExclusive(dir string) (*Lock, error) { return lockFileEx(dir, lockfileExclusiveLock) }

// LockShared takes a shared (reader) lock without blocking. It fails with
// ErrLocked while a writer holds the exclusive lock.
func LockShared(dir string) (*Lock, error) { return lockFileEx(dir, 0) }

// Release drops the lock.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close() // closing the handle releases the lock
	l.f = nil
	return err
}
