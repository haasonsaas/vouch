package posture

// LegacyToV2 converts a legacy Report to ReportV2
// Used for backward compatibility with old agents
func LegacyToV2(r Report) ReportV2 {
	v2 := ReportV2{
		NodeID:   r.NodeID,
		Hostname: r.Hostname,
		OS:       inferOS(r.OSRelease),
		Arch:     "unknown",
		OSName:   r.OSRelease,
		Kernel:   r.Kernel,

		// Updates
		UpdatesOutstanding: 0,
		AutoUpdateEnabled:  false,
		RebootPending:      false,

		// Encryption
		RootVolumeEncrypted: r.DiskEncrypted,
		EncryptionType:      "",

		// Firewall
		FirewallEnabled: r.FirewallEnabled,

		// Tailscale - legacy doesn't have these
		TailscaleOnline: true, // assume online if reporting

		// Services
		CriticalServices: r.Services,

		// Metadata
		CollectedAt: r.Timestamp,
		Errors:      make(map[string]string),
	}

	// Convert LastUpdateTime if present
	if r.LastUpdateTime > 0 {
		v2.LastUpdateTime = &r.LastUpdateTime
	}

	return v2
}

// inferOS attempts to determine OS from OSRelease string
func inferOS(osRelease string) string {
	if osRelease == "" {
		return "unknown"
	}
	// Simple heuristics
	if contains(osRelease, "Ubuntu") || contains(osRelease, "Debian") || contains(osRelease, "Linux") {
		return "linux"
	}
	if contains(osRelease, "macOS") || contains(osRelease, "Darwin") {
		return "darwin"
	}
	if contains(osRelease, "Windows") {
		return "windows"
	}
	return "unknown"
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
