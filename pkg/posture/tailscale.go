package posture

import (
	"encoding/json"
	"os/exec"
)

type TailscalePosture struct {
	Version        string `json:"version"`
	AutoUpdate     bool   `json:"auto_update"`
	ReleaseTrack   string `json:"release_track"`
	StateEncrypted bool   `json:"state_encrypted"`
	NodeID         string `json:"node_id"`
	Online         bool   `json:"online"`
}

func CollectTailscalePosture(localAPISocket string) (*TailscalePosture, error) {
	// Try using tailscale CLI status
	out, err := exec.Command("tailscale", "status", "--json").Output()
	if err != nil {
		return &TailscalePosture{Online: false}, nil
	}

	var status struct {
		Version string `json:"Version"`
		Self    struct {
			ID           string   `json:"ID"`
			Online       bool     `json:"Online"`
			Relay        string   `json:"Relay"`
			RxBytes      int64    `json:"RxBytes"`
			TxBytes      int64    `json:"TxBytes"`
			Created      string   `json:"Created"`
			LastSeen     string   `json:"LastSeen"`
			OS           string   `json:"OS"`
			HostName     string   `json:"HostName"`
			DNSName      string   `json:"DNSName"`
			UserID       int      `json:"UserID"`
			TailscaleIPs []string `json:"TailscaleIPs"`
		} `json:"Self"`
		BackendState   string `json:"BackendState"`
		CurrentTailnet struct {
			Name            string `json:"Name"`
			MagicDNSSuffix  string `json:"MagicDNSSuffix"`
			MagicDNSEnabled bool   `json:"MagicDNSEnabled"`
		} `json:"CurrentTailnet"`
	}

	if err := json.Unmarshal(out, &status); err != nil {
		return &TailscalePosture{Online: false}, err
	}

	// Check if auto-update is enabled (via prefs)
	autoUpdate := false
	releaseTrack := "stable"

	prefsOut, err := exec.Command("tailscale", "debug", "prefs").Output()
	if err == nil {
		var prefs map[string]interface{}
		if err := json.Unmarshal(prefsOut, &prefs); err == nil {
			if au, ok := prefs["AutoUpdate"].(map[string]interface{}); ok {
				if check, ok := au["Check"].(bool); ok {
					autoUpdate = check
				}
			}
		}
	}

	// State encryption check (look for state file encryption)
	stateEncrypted := checkTailscaleStateEncryption()

	return &TailscalePosture{
		Version:        status.Version,
		AutoUpdate:     autoUpdate,
		ReleaseTrack:   releaseTrack,
		StateEncrypted: stateEncrypted,
		NodeID:         status.Self.ID,
		Online:         status.Self.Online,
	}, nil
}

func checkTailscaleStateEncryption() bool {
	// Check if tailscale state file is encrypted
	// This is a placeholder - actual implementation depends on OS
	// Linux: check /var/lib/tailscale/tailscaled.state permissions and content
	// Windows: check registry encryption
	return false
}
