package posture

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type UpdatesPosture struct {
	AutoUpdateEnabled bool      `json:"auto_update_enabled"`
	LastUpdateTime    time.Time `json:"last_update_time"`
	UpdatesOutstanding int      `json:"updates_outstanding"`
	RebootPending     bool      `json:"reboot_pending"`
}

func CollectUpdatesPosture() (*UpdatesPosture, error) {
	if runtime.GOOS == "windows" {
		return collectWindowsUpdates()
	}
	return collectLinuxUpdates()
}

func collectLinuxUpdates() (*UpdatesPosture, error) {
	posture := &UpdatesPosture{}

	// Check for unattended-upgrades (Debian/Ubuntu)
	if _, err := exec.Command("systemctl", "is-enabled", "unattended-upgrades").Output(); err == nil {
		posture.AutoUpdateEnabled = true
	}

	// Check for dnf-automatic (RHEL/Fedora)
	if _, err := exec.Command("systemctl", "is-enabled", "dnf-automatic.timer").Output(); err == nil {
		posture.AutoUpdateEnabled = true
	}

	// Get last update time
	if info, err := os.Stat("/var/lib/apt/lists"); err == nil {
		posture.LastUpdateTime = info.ModTime()
	} else if info, err := os.Stat("/var/cache/dnf"); err == nil {
		posture.LastUpdateTime = info.ModTime()
	} else if info, err := os.Stat("/var/cache/apk"); err == nil {
		posture.LastUpdateTime = info.ModTime()
	}

	// Check for outstanding updates
	if runtime.GOOS == "linux" {
		// apt
		out, err := exec.Command("apt", "list", "--upgradable").Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			posture.UpdatesOutstanding = len(lines) - 2 // Subtract header and empty line
			if posture.UpdatesOutstanding < 0 {
				posture.UpdatesOutstanding = 0
			}
		}
	}

	// Check for pending reboot
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		posture.RebootPending = true
	}

	return posture, nil
}

func collectWindowsUpdates() (*UpdatesPosture, error) {
	posture := &UpdatesPosture{}

	// Check Windows Update service
	out, err := exec.Command("powershell", "-Command",
		"Get-Service -Name wuauserv | Select-Object Status").Output()
	if err == nil {
		posture.AutoUpdateEnabled = strings.Contains(string(out), "Running")
	}

	// Check last update time via registry or WMI
	out, err = exec.Command("powershell", "-Command",
		"(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn").Output()
	if err == nil {
		// Parse time from output
		timeStr := strings.TrimSpace(string(out))
		if t, err := time.Parse("1/2/2006 12:00:00 AM", timeStr); err == nil {
			posture.LastUpdateTime = t
		}
	}

	// Check for pending updates
	out, err = exec.Command("powershell", "-Command",
		"(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().GetTotalHistoryCount()").Output()
	if err == nil {
		// Simplified - would need more robust update checking
		posture.UpdatesOutstanding = 0
	}

	// Check for pending reboot
	out, err = exec.Command("powershell", "-Command",
		"Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'").Output()
	if err == nil {
		posture.RebootPending = strings.Contains(string(out), "True")
	}

	return posture, nil
}
