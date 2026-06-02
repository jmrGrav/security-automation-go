package lock

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireLock_FirstInstance(t *testing.T) {
	tmpDir := t.TempDir()
	lockFile := filepath.Join(tmpDir, "app.pid")

	locker, err := NewFileLock(lockFile)
	if err != nil {
		t.Fatalf("NewFileLock failed: %v", err)
	}

	if err := locker.Acquire(); err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	defer locker.Release()

	// Verify lock file exists
	if _, err := os.Stat(lockFile); err != nil {
		t.Errorf("lock file not created")
	}
}

func TestAcquireLock_SecondInstanceFails(t *testing.T) {
	tmpDir := t.TempDir()
	lockFile := filepath.Join(tmpDir, "app.pid")

	locker1, _ := NewFileLock(lockFile)
	locker1.Acquire()
	defer locker1.Release()

	locker2, _ := NewFileLock(lockFile)
	err := locker2.Acquire()
	if err == nil {
		t.Errorf("expected error for second instance, got nil")
	}
	if !IsPIDLocked(err) {
		t.Errorf("error should be PIDLockedError")
	}
}

func TestGetLockingPID(t *testing.T) {
	tmpDir := t.TempDir()
	lockFile := filepath.Join(tmpDir, "app.pid")

	locker, _ := NewFileLock(lockFile)
	locker.Acquire()
	defer locker.Release()

	locker2, _ := NewFileLock(lockFile)
	err := locker2.Acquire()

	if err != nil {
		pidErr, ok := err.(PIDLockedError)
		if !ok {
			t.Errorf("error is not PIDLockedError")
		}
		if pidErr.PID <= 0 {
			t.Errorf("invalid PID: %d", pidErr.PID)
		}
	}
}

func TestReleaseLock(t *testing.T) {
	tmpDir := t.TempDir()
	lockFile := filepath.Join(tmpDir, "app.pid")

	locker1, _ := NewFileLock(lockFile)
	locker1.Acquire()
	locker1.Release()

	// Second instance should now succeed
	locker2, _ := NewFileLock(lockFile)
	err := locker2.Acquire()
	if err != nil {
		t.Errorf("Acquire after release failed: %v", err)
	}
	locker2.Release()
}
