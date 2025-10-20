package posture

import (
	"os"
	"os/exec"
	"strings"
	"time"
)

type Report struct {
	NodeID         string    `json:"node_id"`
	Hostname       string    `json:"hostname"`
	OSRelease      string    `json:"os_release"`
	Kernel         string    `json:"kernel"`
	LastUpdateTime int64     `json:"last_update_time"`
	DiskEncrypted  bool      `json:"disk_encrypted"`
	Services       []string  `json:"services"`
	Timestamp      time.Time `json:"timestamp"`
}

func Collect() (*Report, error) {
	hostname, _ := os.Hostname()
	
	return &Report{
		NodeID:         getTailscaleNodeID(),
		Hostname:       hostname,
		OSRelease:      getOSRelease(),
		Kernel:         getKernel(),
		LastUpdateTime: getLastUpdateTime(),
		DiskEncrypted:  isDiskEncrypted(),
		Services:       getRunningServices(),
		Timestamp:      time.Now(),
	}, nil
}

func getTailscaleNodeID() string {
	out, err := exec.Command("tailscale", "status", "--json").Output()
	if err != nil {
		return "unknown"
	}
	// Parse JSON and extract node ID
	// Simplified for now
	return strings.TrimSpace(string(out)[:20])
}

func getOSRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	return string(data)
}

func getKernel() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func getLastUpdateTime() int64 {
	// Check apt lists for Debian/Ubuntu
	if info, err := os.Stat("/var/lib/apt/lists"); err == nil {
		return info.ModTime().Unix()
	}
	// Check yum/dnf for RHEL/Fedora
	if info, err := os.Stat("/var/cache/dnf"); err == nil {
		return info.ModTime().Unix()
	}
	return 0
}

func isDiskEncrypted() bool {
	// Check for LUKS/dm-crypt
	_, err := os.Stat("/dev/mapper/cryptroot")
	return err == nil
}

func getRunningServices() []string {
	out, err := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-pager").Output()
	if err != nil {
		return []string{}
	}
	
	services := []string{}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, ".service") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				services = append(services, parts[0])
			}
		}
	}
	return services
}
