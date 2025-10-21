package posture

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type SecureBootPosture struct {
	SecureBootEnabled bool   `json:"secure_boot_enabled"`
	TPMPresent        bool   `json:"tpm_present"`
	TPMVersion        string `json:"tpm_version,omitempty"`
}

func CollectSecureBootPosture() (*SecureBootPosture, error) {
	if runtime.GOOS == "windows" {
		return collectWindowsSecureBoot()
	}
	return collectLinuxSecureBoot()
}

func collectLinuxSecureBoot() (*SecureBootPosture, error) {
	posture := &SecureBootPosture{}

	// Check Secure Boot via EFI vars
	data, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
	if err == nil && len(data) > 4 {
		// Last byte is the value: 1 = enabled, 0 = disabled
		posture.SecureBootEnabled = data[len(data)-1] == 1
	}

	// Check TPM presence
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		posture.TPMPresent = true
		posture.TPMVersion = "2.0" // Assume TPM 2.0 for /dev/tpm0
	} else if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		posture.TPMPresent = true
		posture.TPMVersion = "2.0"
	}

	// Try tpm2_getcap if available
	out, err := exec.Command("tpm2_getcap", "properties-fixed").Output()
	if err == nil && strings.Contains(string(out), "TPM2") {
		posture.TPMPresent = true
		posture.TPMVersion = "2.0"
	}

	return posture, nil
}

func collectWindowsSecureBoot() (*SecureBootPosture, error) {
	posture := &SecureBootPosture{}

	// Check Secure Boot
	out, err := exec.Command("powershell", "-Command", "Confirm-SecureBootUEFI").Output()
	if err == nil {
		posture.SecureBootEnabled = strings.Contains(string(out), "True")
	}

	// Check TPM
	out, err = exec.Command("powershell", "-Command",
		"Get-Tpm | Select-Object TpmPresent,TpmReady | ConvertTo-Json").Output()
	if err == nil {
		var tpm struct {
			TpmPresent bool
			TpmReady   bool
		}
		if json.Unmarshal(out, &tpm) == nil {
			posture.TPMPresent = tpm.TpmPresent
			if tpm.TpmPresent {
				posture.TPMVersion = "2.0" // Modern Windows requires TPM 2.0
			}
		}
	}

	return posture, nil
}
