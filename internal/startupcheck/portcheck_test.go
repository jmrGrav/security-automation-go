package startupcheck

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestCheckPortAvailable_Free(t *testing.T) {
	port := findFreePort(t)
	err := CheckPortAvailable("127.0.0.1", port)
	if err != nil {
		t.Errorf("CheckPortAvailable failed on free port: %v", err)
	}
}

func TestCheckPortAvailable_Occupied(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	err = CheckPortAvailable("127.0.0.1", addr.Port)
	if err == nil {
		t.Errorf("expected error for occupied port, got nil")
	}
}

func TestGetProcessUsingPort(t *testing.T) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	pid, _ := GetProcessUsingPort(addr.Port)
	if pid == 0 {
		t.Logf("could not determine process using port (may require elevated privileges)")
	}
}

func findFreePort(t *testing.T) int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func TestPortInUseErrorMessage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	port := addr.Port

	err = CheckPortAvailable("127.0.0.1", port)
	if err == nil {
		t.Fatalf("expected error for occupied port")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, fmt.Sprintf("%d", port)) {
		t.Errorf("error message should contain port number %d, got: %s", port, errMsg)
	}
	if !strings.Contains(errMsg, "already in use") && !strings.Contains(errMsg, "in use") {
		t.Errorf("error message should say port is in use, got: %s", errMsg)
	}
}
