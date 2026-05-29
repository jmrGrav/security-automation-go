package lock

import (
	"testing"
)

func TestFileLock(t *testing.T) {
	dir := t.TempDir()
	lock1 := NewFileLock(dir)
	lock2 := NewFileLock(dir)

	// 1. Acquire lock 1
	acquired, err := lock1.Acquire()
	if err != nil {
		t.Fatalf("failed to acquire lock 1: %v", err)
	}
	if !acquired {
		t.Fatal("lock 1 should be acquired")
	}

	// 2. Try to acquire lock 2 (should fail)
	acquired, err = lock2.Acquire()
	if err != nil {
		t.Fatalf("error acquiring lock 2: %v", err)
	}
	if acquired {
		t.Fatal("lock 2 should not be acquired while lock 1 is held")
	}

	// 3. Release lock 1
	if err := lock1.Release(); err != nil {
		t.Fatalf("failed to release lock 1: %v", err)
	}

	// 4. Try to acquire lock 2 (should succeed now)
	acquired, err = lock2.Acquire()
	if err != nil {
		t.Fatalf("failed to acquire lock 2 after release: %v", err)
	}
	if !acquired {
		t.Fatal("lock 2 should be acquired after lock 1 release")
	}

	_ = lock2.Release()
}
