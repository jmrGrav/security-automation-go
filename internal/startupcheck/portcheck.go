package startupcheck

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// CheckPortAvailable verifies that a port is not in use.
func CheckPortAvailable(host string, port int) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return PortInUseError{
			Port:     port,
			Host:     host,
			Err:      err,
			PID:      getPIDUsingPort(port),
			ProcName: getProcNameUsingPort(port),
		}
	}
	listener.Close()
	return nil
}

// GetProcessUsingPort attempts to find the PID and process name using the port.
func GetProcessUsingPort(port int) (int, string) {
	return getPIDUsingPort(port), getProcNameUsingPort(port)
}

// getPIDUsingPort returns the PID of the process using the port (platform-dependent).
func getPIDUsingPort(port int) int {
	switch runtime.GOOS {
	case "linux":
		return getPIDLinux(port)
	case "darwin":
		return getPIDDarwin(port)
	default:
		return 0
	}
}

// getProcNameUsingPort returns the process name using the port (platform-dependent).
func getProcNameUsingPort(port int) string {
	switch runtime.GOOS {
	case "linux":
		return getProcNameLinux(port)
	case "darwin":
		return getProcNameDarwin(port)
	default:
		return ""
	}
}

// getPIDLinux uses ss or netstat on Linux.
func getPIDLinux(port int) int {
	// Try ss first (newer systems)
	cmd := exec.Command("ss", "-tlnp", fmt.Sprintf("sport = :%d", port))
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		// Parse output: "tcp  LISTEN  0  128  127.0.0.1:PORT  *:*  users:(("app",pid=1234))"
		parts := strings.Fields(string(output))
		for _, part := range parts {
			if strings.Contains(part, "pid=") {
				pidStr := strings.TrimPrefix(part, "pid=")
				pidStr = strings.TrimSuffix(pidStr, ")")
				if pid, err := strconv.Atoi(pidStr); err == nil {
					return pid
				}
			}
		}
	}
	return 0
}

// getProcNameLinux extracts process name from /proc/PID/comm.
func getProcNameLinux(port int) string {
	pid := getPIDLinux(port)
	if pid == 0 {
		return ""
	}
	commFile := fmt.Sprintf("/proc/%d/comm", pid)
	if data, err := os.ReadFile(commFile); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

// getPIDDarwin uses lsof on macOS.
func getPIDDarwin(port int) int {
	cmd := exec.Command("lsof", "-i", fmt.Sprintf(":%d", port), "-t")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(output))); err == nil {
			return pid
		}
	}
	return 0
}

// getProcNameDarwin extracts process name from lsof.
func getProcNameDarwin(port int) string {
	cmd := exec.Command("lsof", "-i", fmt.Sprintf(":%d", port), "-F", "c")
	output, err := cmd.Output()
	if err == nil && len(output) > 0 {
		// lsof -F output: "cprocess_name\n..."
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "c") {
				return strings.TrimPrefix(line, "c")
			}
		}
	}
	return ""
}

// PortInUseError is returned when a port is already in use.
type PortInUseError struct {
	Port     int
	Host     string
	Err      error
	PID      int
	ProcName string
}

func (e PortInUseError) Error() string {
	msg := fmt.Sprintf("UI port %d already in use", e.Port)
	if e.PID != 0 {
		msg += fmt.Sprintf("\n\nPID: %d", e.PID)
	}
	if e.ProcName != "" {
		msg += fmt.Sprintf("\nProcess: %s", e.ProcName)
	}
	return msg
}
