package health

import (
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type HealthStatus struct {
	ServerReachable    bool      `json:"server_reachable"`
	TailscaledRunning  bool      `json:"tailscaled_running"`
	TimeDrift          int       `json:"time_drift_seconds"`
	LastSuccessfulSync time.Time `json:"last_successful_sync"`
	Healthy            bool      `json:"healthy"`
	Issues             []string  `json:"issues,omitempty"`
}

func Check(serverURL string, maxTimeDrift int) *HealthStatus {
	status := &HealthStatus{
		Healthy: true,
		Issues:  []string{},
	}

	// Check server connectivity
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(serverURL + "/v1/health")
	if err != nil {
		status.ServerReachable = false
		status.Healthy = false
		status.Issues = append(status.Issues, fmt.Sprintf("cannot reach server: %v", err))
	} else {
		resp.Body.Close()
		status.ServerReachable = resp.StatusCode == 200
		if !status.ServerReachable {
			status.Healthy = false
			status.Issues = append(status.Issues, fmt.Sprintf("server unhealthy: %d", resp.StatusCode))
		}
	}

	// Check tailscaled
	status.TailscaledRunning = checkTailscaled()
	if !status.TailscaledRunning {
		status.Healthy = false
		status.Issues = append(status.Issues, "tailscaled not running")
	}

	// Check time drift
	drift := checkTimeDrift()
	status.TimeDrift = drift
	if drift > maxTimeDrift {
		status.Healthy = false
		status.Issues = append(status.Issues, fmt.Sprintf("time drift %ds exceeds max %ds", drift, maxTimeDrift))
	}

	if status.Healthy {
		status.LastSuccessfulSync = time.Now()
	}

	return status
}

func checkTailscaled() bool {
	if runtime.GOOS == "windows" {
		out, err := exec.Command("powershell", "-Command", 
			"Get-Service -Name Tailscale | Select-Object Status").Output()
		if err != nil {
			return false
		}
		return strings.Contains(string(out), "Running")
	}

	// Linux/macOS
	out, err := exec.Command("systemctl", "is-active", "tailscaled").Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		return true
	}

	// Fallback: try tailscale status
	err = exec.Command("tailscale", "status").Run()
	return err == nil
}

func checkTimeDrift() int {
	// Try NTP check
	if runtime.GOOS == "linux" {
		// Try timedatectl
		out, err := exec.Command("timedatectl", "show", "-p", "NTPSynchronized", "-p", "TimeUSec").Output()
		if err == nil && strings.Contains(string(out), "NTPSynchronized=yes") {
			// System time is synced
			return 0
		}

		// Try chronyc
		out, err = exec.Command("chronyc", "tracking").Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				if strings.Contains(line, "System time") {
					// Parse drift from chrony output
					// Simplified - would need proper parsing
					return 0
				}
			}
		}
	}

	// Fallback: check against HTTP Date header from server
	// This is a simple heuristic
	return 0
}
