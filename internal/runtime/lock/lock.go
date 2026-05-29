package lock

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/jm/security-automation-go/internal/apperr"
)

// FileLock prevents concurrent process execution using flock.
type FileLock struct {
	path string
	file *os.File
}

func NewFileLock(dir string) *FileLock {
	return &FileLock{
		path: filepath.Join(dir, "daemon.lock"),
	}
}

func (l *FileLock) Acquire() (bool, error) {
	const op = "runtime.lock.Acquire"

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return false, apperr.Wrap(op, err)
	}
	l.file = f

	// Attempt non-blocking exclusive lock
	err = syscall.Flock(int(l.file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		if err == syscall.EWOULDBLOCK {
			_ = l.file.Close()
			return false, nil
		}
		return false, apperr.Wrap(op, err)
	}

	// Write current PID for debugging
	_ = l.file.Truncate(0)
	_, _ = l.file.Seek(0, 0)
	_, _ = fmt.Fprintf(l.file, "%d", os.Getpid())

	return true, nil
}

func (l *FileLock) Release() error {
	const op = "runtime.lock.Release"
	if l.file == nil {
		return nil
	}

	err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
	l.file = nil
	return apperr.Wrap(op, err)
}
