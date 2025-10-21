package posture

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ReportV2 contains comprehensive device posture with partial failure support
type ReportV2 struct {
	// Identity
	NodeID   string `json:"node_id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`   // linux, darwin, windows
	Arch     string `json:"arch"` // amd64, arm64

	// OS Info
	OSName string `json:"os_name"` // Ubuntu 24.04, macOS 14.5, Windows 11
	Kernel string `json:"kernel"`  // 6.8.0-47-generic

	// Updates
	LastUpdateTime     *time.Time `json:"last_update_time,omitempty"`
	UpdatesOutstanding int        `json:"updates_outstanding"`
	AutoUpdateEnabled  bool       `json:"auto_update_enabled"`
	RebootPending      bool       `json:"reboot_pending"`

	// Disk Encryption
	RootVolumeEncrypted bool     `json:"root_volume_encrypted"`
	EncryptedVolumes    []string `json:"encrypted_volumes,omitempty"`
	EncryptionType      string   `json:"encryption_type,omitempty"` // luks, filevault, bitlocker

	// Tailscale
	TailscaleVersion    string `json:"tailscale_version,omitempty"`
	TailscaleOnline     bool   `json:"tailscale_online"`
	TailscaleAutoUpdate bool   `json:"tailscale_auto_update"`

	// Firewall
	FirewallEnabled bool   `json:"firewall_enabled"`
	FirewallType    string `json:"firewall_type,omitempty"` // ufw, nftables, iptables, pf, windows-defender

	// Security
	SecureBootEnabled    bool   `json:"secure_boot_enabled"`
	TPMPresent           bool   `json:"tpm_present"`
	TPMVersion           string `json:"tpm_version,omitempty"`
	SentinelOneInstalled bool   `json:"sentinelone_installed"`
	SentinelOneHealthy   bool   `json:"sentinelone_healthy"`
	SentinelOneVersion   string `json:"sentinelone_version,omitempty"`
	CrowdStrikeInstalled bool   `json:"crowdstrike_installed"`
	CrowdStrikeHealthy   bool   `json:"crowdstrike_healthy"`
	CrowdStrikeVersion   string `json:"crowdstrike_version,omitempty"`

	// Services (top 10 most relevant)
	CriticalServices []string `json:"critical_services,omitempty"`

	// Metadata
	CollectedAt time.Time         `json:"collected_at"`
	Errors      map[string]string `json:"errors,omitempty"` // probe_name -> error_message
}

// CollectorV2 runs posture checks with timeouts and parallel execution
type CollectorV2 struct {
	timeout time.Duration
	errors  map[string]string
	mu      sync.Mutex
}

func NewCollectorV2(timeout time.Duration) *CollectorV2 {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &CollectorV2{
		timeout: timeout,
		errors:  make(map[string]string),
	}
}

// CollectV2 runs all posture checks in parallel with timeouts
func (c *CollectorV2) Collect(ctx context.Context) *ReportV2 {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	report := &ReportV2{
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		CollectedAt: time.Now(),
		Errors:      make(map[string]string),
	}

	hostname, _ := os.Hostname()
	report.Hostname = hostname

	// Run probes in parallel
	var wg sync.WaitGroup
	probes := []struct {
		name string
		fn   func(context.Context, *ReportV2)
	}{
		{"os_info", c.probeOSInfo},
		{"kernel", c.probeKernel},
		{"updates", c.probeUpdates},
		{"disk_encryption", c.probeDiskEncryption},
		{"tailscale", c.probeTailscale},
		{"firewall", c.probeFirewall},
		{"secure_boot", c.probeSecureBoot},
		{"edr", c.probeEDR},
		{"services", c.probeServices},
	}

	for _, probe := range probes {
		wg.Add(1)
		go func(name string, fn func(context.Context, *ReportV2)) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					c.recordError(name, fmt.Sprintf("panic: %v", r))
				}
			}()
			fn(ctx, report)
		}(probe.name, probe.fn)
	}

	wg.Wait()

	// Copy errors to report
	c.mu.Lock()
	report.Errors = c.errors
	c.mu.Unlock()

	return report
}

func (c *CollectorV2) recordError(probe, err string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors[probe] = err
}

func (c *CollectorV2) probeOSInfo(ctx context.Context, r *ReportV2) {
	switch runtime.GOOS {
	case "linux":
		// Parse /etc/os-release for PRETTY_NAME
		data, err := os.ReadFile("/etc/os-release")
		if err != nil {
			c.recordError("os_info", err.Error())
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				r.OSName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				return
			}
		}
	case "darwin":
		out, err := execWithTimeout(ctx, "sw_vers", "-productVersion")
		if err == nil {
			r.OSName = "macOS " + strings.TrimSpace(string(out))
		}
	case "windows":
		out, err := execWithTimeout(ctx, "powershell", "-Command",
			"(Get-CimInstance Win32_OperatingSystem).Caption")
		if err == nil {
			r.OSName = strings.TrimSpace(string(out))
		}
	}
}

func (c *CollectorV2) probeKernel(ctx context.Context, r *ReportV2) {
	out, err := execWithTimeout(ctx, "uname", "-r")
	if err != nil {
		c.recordError("kernel", err.Error())
		return
	}
	r.Kernel = strings.TrimSpace(string(out))
}

func (c *CollectorV2) probeUpdates(ctx context.Context, r *ReportV2) {
	switch runtime.GOOS {
	case "linux":
		c.probeLinuxUpdates(ctx, r)
	case "darwin":
		c.probeMacOSUpdates(ctx, r)
	case "windows":
		c.probeWindowsUpdates(ctx, r)
	}
}

func (c *CollectorV2) probeLinuxUpdates(ctx context.Context, r *ReportV2) {
	// Check auto-update services
	services := []string{
		"unattended-upgrades",
		"dnf-automatic.timer",
		"packagekit",
	}
	for _, svc := range services {
		if out, err := execWithTimeout(ctx, "systemctl", "is-enabled", svc); err == nil {
			if strings.Contains(string(out), "enabled") {
				r.AutoUpdateEnabled = true
				break
			}
		}
	}

	// Last update time - try multiple package managers
	paths := []string{
		"/var/lib/apt/lists",   // Debian/Ubuntu
		"/var/cache/dnf",       // RHEL/Fedora
		"/var/lib/pacman/sync", // Arch
		"/var/cache/apk",       // Alpine
		"/var/lib/dpkg/status", // Debian/Ubuntu fallback
	}

	for _, path := range paths {
		if info, err := os.Stat(path); err == nil {
			t := info.ModTime()
			r.LastUpdateTime = &t
			break
		}
	}

	// Check for pending reboot
	_, err := os.Stat("/var/run/reboot-required")
	r.RebootPending = (err == nil)

	// Count outstanding updates (best-effort)
	if out, err := execWithTimeout(ctx, "apt", "list", "--upgradable"); err == nil {
		lines := strings.Split(string(out), "\n")
		r.UpdatesOutstanding = max(0, len(lines)-2)
	}
}

func (c *CollectorV2) probeMacOSUpdates(ctx context.Context, r *ReportV2) {
	// Check for available updates
	out, err := execWithTimeout(ctx, "softwareupdate", "-l")
	if err == nil {
		r.UpdatesOutstanding = strings.Count(string(out), "recommended")
	}

	// Auto-update status
	out, err = execWithTimeout(ctx, "defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled")
	if err == nil && strings.TrimSpace(string(out)) == "1" {
		r.AutoUpdateEnabled = true
	}
}

func (c *CollectorV2) probeWindowsUpdates(ctx context.Context, r *ReportV2) {
	// Windows Update service running
	out, err := execWithTimeout(ctx, "powershell", "-Command",
		"(Get-Service -Name wuauserv).Status")
	if err == nil && strings.Contains(string(out), "Running") {
		r.AutoUpdateEnabled = true
	}

	// Last update
	out, err = execWithTimeout(ctx, "powershell", "-Command",
		"(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn")
	if err == nil {
		if t, err := time.Parse("1/2/2006", strings.TrimSpace(string(out))); err == nil {
			r.LastUpdateTime = &t
		}
	}

	// Pending reboot
	_, err = execWithTimeout(ctx, "powershell", "-Command",
		"Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'")
	r.RebootPending = (err == nil)
}

func (c *CollectorV2) probeDiskEncryption(ctx context.Context, r *ReportV2) {
	switch runtime.GOOS {
	case "linux":
		c.probeLinuxEncryption(ctx, r)
	case "darwin":
		c.probeMacOSEncryption(ctx, r)
	case "windows":
		c.probeWindowsEncryption(ctx, r)
	}
}

func (c *CollectorV2) probeLinuxEncryption(ctx context.Context, r *ReportV2) {
	// Check for LUKS/dm-crypt volumes
	out, err := execWithTimeout(ctx, "lsblk", "-o", "NAME,TYPE,FSTYPE", "-J")
	if err != nil {
		// Fallback to simple check
		if _, err := os.Stat("/dev/mapper/cryptroot"); err == nil {
			r.RootVolumeEncrypted = true
			r.EncryptionType = "luks"
		}
		return
	}

	var lsblk struct {
		Blockdevices []struct {
			Name   string `json:"name"`
			Type   string `json:"type"`
			FSType string `json:"fstype"`
		} `json:"blockdevices"`
	}

	if err := json.Unmarshal(out, &lsblk); err == nil {
		for _, dev := range lsblk.Blockdevices {
			if dev.FSType == "crypto_LUKS" || dev.Type == "crypt" {
				r.EncryptedVolumes = append(r.EncryptedVolumes, dev.Name)
				r.EncryptionType = "luks"
				if strings.Contains(dev.Name, "root") || strings.Contains(dev.Name, "crypt") {
					r.RootVolumeEncrypted = true
				}
			}
		}
	}
}

func (c *CollectorV2) probeMacOSEncryption(ctx context.Context, r *ReportV2) {
	out, err := execWithTimeout(ctx, "fdesetup", "status")
	if err == nil && strings.Contains(string(out), "FileVault is On") {
		r.RootVolumeEncrypted = true
		r.EncryptionType = "filevault"
		r.EncryptedVolumes = []string{"/"}
	}
}

func (c *CollectorV2) probeWindowsEncryption(ctx context.Context, r *ReportV2) {
	out, err := execWithTimeout(ctx, "powershell", "-Command",
		"Get-BitLockerVolume | Where-Object {$_.VolumeType -eq 'OperatingSystem'} | Select-Object -ExpandProperty ProtectionStatus")
	if err == nil && strings.Contains(string(out), "On") {
		r.RootVolumeEncrypted = true
		r.EncryptionType = "bitlocker"
	}
}

func (c *CollectorV2) probeTailscale(ctx context.Context, r *ReportV2) {
	out, err := execWithTimeout(ctx, "tailscale", "status", "--json")
	if err != nil {
		c.recordError("tailscale", err.Error())
		return
	}

	var status struct {
		Version string `json:"Version"`
		Self    struct {
			ID     string `json:"ID"`
			Online bool   `json:"Online"`
		} `json:"Self"`
		BackendState string `json:"BackendState"`
	}

	if err := json.Unmarshal(out, &status); err != nil {
		c.recordError("tailscale", "failed to parse status: "+err.Error())
		return
	}

	r.TailscaleVersion = status.Version
	r.NodeID = status.Self.ID
	r.TailscaleOnline = status.Self.Online

	// Check auto-update (best-effort via prefs)
	if out, err := execWithTimeout(ctx, "tailscale", "debug", "prefs"); err == nil {
		var prefs map[string]interface{}
		if err := json.Unmarshal(out, &prefs); err == nil {
			if au, ok := prefs["AutoUpdate"].(map[string]interface{}); ok {
				if check, ok := au["Check"].(bool); ok {
					r.TailscaleAutoUpdate = check
				}
			}
		}
	}
}

func (c *CollectorV2) probeFirewall(ctx context.Context, r *ReportV2) {
	switch runtime.GOOS {
	case "linux":
		c.probeLinuxFirewall(ctx, r)
	case "darwin":
		c.probeMacOSFirewall(ctx, r)
	case "windows":
		c.probeWindowsFirewall(ctx, r)
	}
}

func (c *CollectorV2) probeLinuxFirewall(ctx context.Context, r *ReportV2) {
	// Try ufw first
	if out, err := execWithTimeout(ctx, "ufw", "status"); err == nil {
		if strings.Contains(string(out), "Status: active") {
			r.FirewallEnabled = true
			r.FirewallType = "ufw"
			return
		}
	}

	// Try nftables
	if out, err := execWithTimeout(ctx, "nft", "list", "ruleset"); err == nil && len(out) > 50 {
		r.FirewallEnabled = true
		r.FirewallType = "nftables"
		return
	}

	// Fallback to iptables
	if out, err := execWithTimeout(ctx, "iptables", "-L", "-n"); err == nil {
		// Check if there are actual rules (not just default chains)
		if len(out) > 200 {
			r.FirewallEnabled = true
			r.FirewallType = "iptables"
		}
	}
}

func (c *CollectorV2) probeMacOSFirewall(ctx context.Context, r *ReportV2) {
	out, err := execWithTimeout(ctx, "defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate")
	if err == nil {
		state := strings.TrimSpace(string(out))
		r.FirewallEnabled = (state == "1" || state == "2")
		r.FirewallType = "pf"
	}
}

func (c *CollectorV2) probeWindowsFirewall(ctx context.Context, r *ReportV2) {
	out, err := execWithTimeout(ctx, "powershell", "-Command",
		"Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 'True'} | Select-Object -ExpandProperty Name")
	if err == nil && len(out) > 0 {
		r.FirewallEnabled = true
		r.FirewallType = "windows-defender"
	}
}

func (c *CollectorV2) probeSecureBoot(ctx context.Context, r *ReportV2) {
	switch runtime.GOOS {
	case "linux":
		// Secure Boot via EFI vars
		data, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
		if err == nil && len(data) > 4 && data[len(data)-1] == 1 {
			r.SecureBootEnabled = true
		}

		// TPM detection
		if _, err := os.Stat("/dev/tpm0"); err == nil {
			r.TPMPresent = true
			r.TPMVersion = "2.0"
		} else if _, err := os.Stat("/dev/tpmrm0"); err == nil {
			r.TPMPresent = true
			r.TPMVersion = "2.0"
		}

	case "darwin":
		// Macs use T2/Apple Silicon secure enclave - always "secure boot" equivalent
		r.SecureBootEnabled = true
		r.TPMPresent = true
		r.TPMVersion = "secure-enclave"

	case "windows":
		// Secure Boot
		out, err := execWithTimeout(ctx, "powershell", "-Command", "Confirm-SecureBootUEFI")
		if err == nil && strings.Contains(string(out), "True") {
			r.SecureBootEnabled = true
		}

		// TPM
		out, err = execWithTimeout(ctx, "powershell", "-Command",
			"(Get-Tpm).TpmPresent")
		if err == nil && strings.Contains(string(out), "True") {
			r.TPMPresent = true
			r.TPMVersion = "2.0"
		}
	}
}

func (c *CollectorV2) probeServices(ctx context.Context, r *ReportV2) {
	// List critical services only (SSH, Docker, etc.)
	critical := []string{"sshd", "docker", "dockerd", "tailscaled"}

	for _, svc := range critical {
		out, err := execWithTimeout(ctx, "systemctl", "is-active", svc)
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			r.CriticalServices = append(r.CriticalServices, svc)
		}
	}
}

var commandRunner = execWithTimeout

func probeSentinelOneLinux(ctx context.Context, r *ReportV2, c *CollectorV2) {
	if _, err := exec.LookPath("sentinelctl"); err == nil {
		r.SentinelOneInstalled = true
		if versionOut, err := commandRunner(ctx, "sentinelctl", "version"); err == nil {
			r.SentinelOneVersion = parseSentinelOneVersion(string(versionOut))
		} else {
			c.recordError("sentinelone", err.Error())
		}
		if out, err := commandRunner(ctx, "systemctl", "is-active", "sentinelone-agent"); err == nil {
			r.SentinelOneHealthy = strings.TrimSpace(string(out)) == "active"
		}
	}
}

func probeSentinelOneMac(ctx context.Context, r *ReportV2, c *CollectorV2) {
	agentPath := "/Library/Sentinel/sentinel-agent.bundle"
	if _, err := os.Stat(agentPath); err == nil {
		r.SentinelOneInstalled = true
		versionPath := filepath.Join(agentPath, "Contents", "Info.plist")
		if data, err := os.ReadFile(versionPath); err == nil {
			if ver := extractPlistVersion(string(data)); ver != "" {
				r.SentinelOneVersion = ver
			}
		}
		ctlPath := "/usr/bin/sentinelctl"
		if _, err := os.Stat(ctlPath); err == nil {
			if out, err := commandRunner(ctx, ctlPath, "status"); err == nil {
				lower := strings.ToLower(string(out))
				r.SentinelOneHealthy = strings.Contains(lower, "running") || strings.Contains(lower, "active")
			} else {
				c.recordError("sentinelone", err.Error())
			}
		} else {
			if out, err := commandRunner(ctx, "launchctl", "list", "com.sentinelone.sentinel-agent"); err == nil {
				r.SentinelOneHealthy = strings.Contains(strings.ToLower(string(out)), "running")
			}
		}
	}
}

func probeSentinelOneWindows(ctx context.Context, r *ReportV2, c *CollectorV2) {
	if out, err := commandRunner(ctx, "powershell", "-Command", "Get-Service -Name 'Sentinel Agent' -ErrorAction SilentlyContinue"); err == nil && len(out) > 0 {
		r.SentinelOneInstalled = true
		if statusOut, err := commandRunner(ctx, "powershell", "-Command", "(Get-Service -Name 'Sentinel Agent').Status"); err == nil {
			r.SentinelOneHealthy = strings.Contains(string(statusOut), "Running")
		}
		if versionOut, err := commandRunner(ctx, "powershell", "-Command", "(Get-ChildItem 'C:/Program Files/SentinelOne' -Directory | Select-Object -First 1 | Get-ChildItem -Filter 'SentinelAgent.exe' -Recurse | Select-Object -First 1).VersionInfo.ProductVersion"); err == nil {
			r.SentinelOneVersion = strings.TrimSpace(string(versionOut))
		}
	}
}

func probeCrowdStrikeLinux(ctx context.Context, r *ReportV2, c *CollectorV2) {
	if _, err := exec.LookPath("falconctl"); err == nil {
		r.CrowdStrikeInstalled = true
		if out, err := commandRunner(ctx, "falconctl", "-g", "--version"); err == nil {
			r.CrowdStrikeVersion = parseCrowdStrikeVersion(string(out))
		} else {
			c.recordError("crowdstrike", err.Error())
		}
		if out, err := commandRunner(ctx, "systemctl", "is-active", "falcon-sensor"); err == nil {
			r.CrowdStrikeHealthy = strings.TrimSpace(string(out)) == "active"
		}
	}
}

func probeCrowdStrikeMac(ctx context.Context, r *ReportV2, c *CollectorV2) {
	sensorPath := "/Library/CS/falconctl"
	if _, err := os.Stat(sensorPath); err == nil {
		r.CrowdStrikeInstalled = true
		if out, err := commandRunner(ctx, sensorPath, "stats"); err == nil {
			r.CrowdStrikeHealthy = strings.Contains(strings.ToLower(string(out)), "running")
		} else {
			c.recordError("crowdstrike", err.Error())
		}
		if out, err := commandRunner(ctx, sensorPath, "stats", "--version"); err == nil {
			r.CrowdStrikeVersion = parseCrowdStrikeVersion(string(out))
		}
	}
}

func probeCrowdStrikeWindows(ctx context.Context, r *ReportV2, c *CollectorV2) {
	if out, err := commandRunner(ctx, "powershell", "-Command", "Get-Service -Name 'CSFalconService' -ErrorAction SilentlyContinue"); err == nil && len(out) > 0 {
		r.CrowdStrikeInstalled = true
		if statusOut, err := commandRunner(ctx, "powershell", "-Command", "(Get-Service -Name 'CSFalconService').Status"); err == nil {
			r.CrowdStrikeHealthy = strings.Contains(string(statusOut), "Running")
		}
		if versionOut, err := commandRunner(ctx, "powershell", "-Command", "(Get-ChildItem 'C:/Program Files/CrowdStrike/Falcon' -Filter 'CSFalconService.exe' -Recurse | Select-Object -First 1).VersionInfo.ProductVersion"); err == nil {
			r.CrowdStrikeVersion = strings.TrimSpace(string(versionOut))
		}
	}
}

func parseSentinelOneVersion(output string) string {
	re := regexp.MustCompile(`(?i)version[:\s]+([\w.\-]+)`)
	if match := re.FindStringSubmatch(output); len(match) > 1 {
		return match[1]
	}
	return strings.TrimSpace(output)
}

func parseCrowdStrikeVersion(output string) string {
	re := regexp.MustCompile(`(?i)(version|sensor version)[:\s]+([\w.\-]+)`)
	if match := re.FindStringSubmatch(output); len(match) > 2 {
		return match[2]
	}
	return strings.TrimSpace(output)
}

func extractPlistVersion(plist string) string {
	re := regexp.MustCompile(`<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>`)
	if match := re.FindStringSubmatch(plist); len(match) > 1 {
		return match[1]
	}
	return ""
}

func (c *CollectorV2) probeEDR(ctx context.Context, r *ReportV2) {
	switch runtime.GOOS {
	case "linux":
		probeSentinelOneLinux(ctx, r, c)
		probeCrowdStrikeLinux(ctx, r, c)
	case "darwin":
		probeSentinelOneMac(ctx, r, c)
		probeCrowdStrikeMac(ctx, r, c)
	case "windows":
		probeSentinelOneWindows(ctx, r, c)
		probeCrowdStrikeWindows(ctx, r, c)
	}
}

// execWithTimeout runs a command with context timeout
func execWithTimeout(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
