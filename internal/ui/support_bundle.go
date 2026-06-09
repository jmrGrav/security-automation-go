package ui

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/detect"
	"github.com/jm/security-automation-go/internal/health"
)

// secretRedactPattern matches lines containing common secret markers.
var secretRedactPattern = regexp.MustCompile(`(?i)(token|password|api[_-]key|secret|private[_-]key)(\s*[=:]\s*)\S+`)

func redactSecretLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if secretRedactPattern.MatchString(line) {
			lines[i] = secretRedactPattern.ReplaceAllString(line, "${1}${2}<REDACTED>")
		}
	}
	return strings.Join(lines, "\n")
}

func (s *Server) handleSupportBundle(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.getSession(r); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	now := time.Now().UTC()
	filename := "support-bundle-" + now.Format("20060102") + ".tar.gz"
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	gw := gzip.NewWriter(w)
	tw := tar.NewWriter(gw)

	// health.json — health checks and detection results (no secret values)
	checks := health.RunAll(s.buildHealthConfig())
	detectors := detect.RunAll(s.buildDetectConfig())
	healthReport := map[string]any{
		"generated_at": now.Format(time.RFC3339),
		"health":       checks,
		"detection":    detectors,
	}
	if data, err := json.MarshalIndent(healthReport, "", "  "); err == nil {
		_ = bundleWriteEntry(tw, "health.json", data, now)
	}

	// runtime-info.json
	info := map[string]string{
		"generated_at": now.Format(time.RFC3339),
		"state_dir":    s.cfg.StateDir,
		"ui_addr":      s.cfg.UI.Addr,
		"ui_enabled":   fmt.Sprintf("%v", s.cfg.UI.Enabled),
	}
	if data, err := json.MarshalIndent(info, "", "  "); err == nil {
		_ = bundleWriteEntry(tw, "runtime-info.json", data, now)
	}

	// systemd status (redacted)
	if out, err := bundleRunCommand("systemctl", "status", "cf-sync", "--no-pager"); err == nil {
		_ = bundleWriteEntry(tw, "systemd-cf-sync.txt", []byte(redactSecretLines(out)), now)
	}

	// Last 200 lines of log, redacted
	logPath := filepath.Join("/var/log/security-automation-go", "cf-sync.log")
	if content, err := bundleReadTail(logPath, 200); err == nil {
		_ = bundleWriteEntry(tw, "cf-sync.log.redacted", []byte(redactSecretLines(content)), now)
	}

	_ = tw.Close()
	_ = gw.Close()
}

func bundleWriteEntry(tw *tar.Writer, name string, data []byte, modtime time.Time) error {
	if err := tw.WriteHeader(&tar.Header{
		Name:    name,
		Mode:    0o640,
		Size:    int64(len(data)),
		ModTime: modtime,
	}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func bundleRunCommand(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func bundleReadTail(path string, n int) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n"), nil
}
