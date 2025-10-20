package posture

import (
	"os/exec"
	"runtime"
	"strings"
)

type FirewallPosture struct {
	Enabled        bool   `json:"enabled"`
	Type           string `json:"type"` // ufw, iptables, nftables, windows-defender
	DefaultPolicy  string `json:"default_policy"`
	ActiveProfiles []string `json:"active_profiles,omitempty"` // Windows
}

func CollectFirewallPosture(prefer string) (*FirewallPosture, error) {
	if runtime.GOOS == "windows" {
		return collectWindowsFirewall()
	}
	return collectLinuxFirewall(prefer)
}

func collectLinuxFirewall(prefer string) (*FirewallPosture, error) {
	// Try ufw first
	if prefer == "ufw" || prefer == "auto" {
		out, err := exec.Command("ufw", "status").Output()
		if err == nil {
			status := string(out)
			enabled := strings.Contains(status, "Status: active")
			return &FirewallPosture{
				Enabled:       enabled,
				Type:          "ufw",
				DefaultPolicy: parseUFWDefaultPolicy(status),
			}, nil
		}
	}

	// Try nftables
	if prefer == "nftables" || prefer == "auto" {
		out, err := exec.Command("nft", "list", "ruleset").Output()
		if err == nil && len(out) > 0 {
			return &FirewallPosture{
				Enabled:       true,
				Type:          "nftables",
				DefaultPolicy: "configured",
			}, nil
		}
	}

	// Fallback to iptables
	out, err := exec.Command("iptables", "-L", "-n").Output()
	if err != nil {
		return &FirewallPosture{Enabled: false, Type: "unknown"}, nil
	}

	hasRules := len(out) > 200 // Basic heuristic
	return &FirewallPosture{
		Enabled:       hasRules,
		Type:          "iptables",
		DefaultPolicy: parseIPTablesDefaultPolicy(string(out)),
	}, nil
}

func collectWindowsFirewall() (*FirewallPosture, error) {
	// PowerShell: Get-NetFirewallProfile
	out, err := exec.Command("powershell", "-Command", 
		"Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json").Output()
	if err != nil {
		return &FirewallPosture{Enabled: false, Type: "windows-defender"}, nil
	}

	var profiles []struct {
		Name    string
		Enabled bool
	}
	
	if err := json.Unmarshal(out, &profiles); err != nil {
		return &FirewallPosture{Enabled: false, Type: "windows-defender"}, nil
	}

	enabled := false
	activeProfiles := []string{}
	for _, p := range profiles {
		if p.Enabled {
			enabled = true
			activeProfiles = append(activeProfiles, p.Name)
		}
	}

	return &FirewallPosture{
		Enabled:        enabled,
		Type:           "windows-defender",
		ActiveProfiles: activeProfiles,
		DefaultPolicy:  "configured",
	}, nil
}

func parseUFWDefaultPolicy(status string) string {
	if strings.Contains(status, "Default: deny") {
		return "deny"
	}
	return "unknown"
}

func parseIPTablesDefaultPolicy(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Chain INPUT") {
			if strings.Contains(line, "policy DROP") {
				return "drop"
			}
			if strings.Contains(line, "policy ACCEPT") {
				return "accept"
			}
		}
	}
	return "unknown"
}
