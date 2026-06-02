package lock

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// FileLock implements single-instance protection via a PID lock file.
type FileLock struct {
	path string
	file *os.File
}

// NewFileLock creates a new file lock.
func NewFileLock(path string) (*FileLock, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}
	return &FileLock{path: path}, nil
}

// Acquire acquires the lock. Returns PIDLockedError if another instance holds it.
func (l *FileLock) Acquire() error {
	// Try to open file with exclusive access
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			// File exists — another instance may be running
			pid, err := l.readLockingPID()
			if err == nil {
				// Verify process is actually running
				if isProcessRunning(pid) {
					return PIDLockedError{PID: pid, Path: l.path}
				}
				// Process is not running — remove stale lock and retry
				_ = os.Remove(l.path)
				return l.Acquire()
			}
		}
		return fmt.Errorf("acquire lock: %w", err)
	}

	// Write our PID to the lock file
	if _, err := fmt.Fprintf(f, "%d\n", os.Getpid()); err != nil {
		f.Close()
		return fmt.Errorf("write pid: %w", err)
	}

	l.file = f
	return nil
}

// Release releases the lock.
func (l *FileLock) Release() error {
	if l.file != nil {
		l.file.Close()
	}
	return os.Remove(l.path)
}

// readLockingPID reads the PID from the lock file.
func (l *FileLock) readLockingPID() (int, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return 0, fmt.Errorf("read lock file: %w", err)
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return 0, fmt.Errorf("parse pid: %w", err)
	}

	return pid, nil
}

// isProcessRunning checks if a process is running.
func isProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	defer process.Release()

	// Send signal 0 to check if process exists
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// PIDLockedError is returned when another instance holds the lock.
type PIDLockedError struct {
	PID  int
	Path string
}

func (e PIDLockedError) Error() string {
	return fmt.Sprintf("another instance (PID %d) holds lock %s", e.PID, e.Path)
}

// IsPIDLocked checks if an error is a PIDLockedError.
func IsPIDLocked(err error) bool {
	_, ok := err.(PIDLockedError)
	return ok
}
