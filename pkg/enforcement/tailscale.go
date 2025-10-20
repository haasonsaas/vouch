package enforcement

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type TailscaleEnforcer struct {
	apiKey   string
	tailnet  string
	tagName  string
	client   *http.Client
}

type ACLUpdate struct {
	ACLs []ACLRule `json:"acls"`
}

type ACLRule struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
}

func NewTailscaleEnforcer(apiKey, tailnet, tagName string) *TailscaleEnforcer {
	if apiKey == "" {
		apiKey = os.Getenv("TAILSCALE_API_KEY")
	}
	if tagName == "" {
		tagName = "tag:compliant"
	}

	return &TailscaleEnforcer{
		apiKey:  apiKey,
		tailnet: tailnet,
		tagName: tagName,
		client:  &http.Client{},
	}
}

// GrantAccess adds the compliant tag to a device
func (e *TailscaleEnforcer) GrantAccess(nodeID string) error {
	return e.updateNodeTags(nodeID, []string{e.tagName}, []string{})
}

// RevokeAccess removes the compliant tag from a device
func (e *TailscaleEnforcer) RevokeAccess(nodeID string) error {
	return e.updateNodeTags(nodeID, []string{}, []string{e.tagName})
}

func (e *TailscaleEnforcer) updateNodeTags(nodeID string, addTags, removeTags []string) error {
	url := fmt.Sprintf("https://api.tailscale.com/api/v2/device/%s/tags", nodeID)

	payload := map[string]interface{}{
		"tags": addTags,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+e.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("tailscale API returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetDeviceInfo fetches device info from Tailscale API
func (e *TailscaleEnforcer) GetDeviceInfo(nodeID string) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://api.tailscale.com/api/v2/device/%s", nodeID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+e.apiKey)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tailscale API returned %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}
