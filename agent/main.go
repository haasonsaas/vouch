package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/haasonsaas/vouch/pkg/auth"
	"github.com/haasonsaas/vouch/pkg/config"
	"github.com/haasonsaas/vouch/pkg/health"
	"github.com/haasonsaas/vouch/pkg/posture"
)

var (
	configPath  = flag.String("config", "/etc/vouch/agent.yaml", "Config file path")
	serverURL   = flag.String("server", "", "Vouch server URL (overrides config)")
	interval    = flag.Duration("interval", 0, "Report interval (overrides config)")
	enrollToken = flag.String("enroll", "", "One-time enrollment token")
	Version     = "dev"
)

type Agent struct {
	config   *config.AgentConfig
	identity *auth.Identity
	client   *http.Client
	keyPath  string
}

func main() {
	flag.Parse()

	log.Printf("Vouch Agent %s starting...", Version)

	// Load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// CLI overrides
	if *serverURL != "" {
		cfg.Server.URL = *serverURL
	}
	if *interval > 0 {
		cfg.Reporting.Interval = int(interval.Seconds())
	}
	if *enrollToken != "" {
		cfg.Server.EnrollToken = *enrollToken
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	agent := &Agent{
		config: cfg,
		client: &http.Client{
			Timeout: time.Duration(cfg.Server.RequestTimeout) * time.Second,
		},
		keyPath: cfg.Auth.KeyPath,
	}

	// Load or enroll identity
	if err := agent.loadOrEnroll(); err != nil {
		log.Fatalf("Failed to initialize identity: %v", err)
	}

	log.Printf("Agent ID: %s", agent.identity.AgentID)
	log.Printf("Node ID: %s", agent.identity.NodeID)
	log.Printf("Server: %s", cfg.Server.URL)
	log.Printf("Report interval: %ds", cfg.Reporting.Interval)

	// Run health check
	healthStatus := health.Check(cfg.Server.URL, cfg.Health.TimeDriftMaxS)
	if !healthStatus.Healthy {
		log.Printf("⚠️  Health issues detected: %v", healthStatus.Issues)
	}

	// Report immediately on startup
	agent.reportPosture()

	// Then report on interval with jitter
	jitter := time.Duration(cfg.Reporting.Jitter) * time.Second
	ticker := time.NewTicker(time.Duration(cfg.Reporting.Interval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Add jitter to avoid thundering herd
		if jitter > 0 {
			time.Sleep(time.Duration(rand.Int63n(int64(jitter))))
		}
		agent.reportPosture()
	}
}

func (a *Agent) loadOrEnroll() error {
	// Try loading existing identity
	identity, err := auth.LoadIdentity(a.keyPath)
	if err == nil {
		a.identity = identity
		log.Printf("✅ Loaded existing identity")
		if a.config.Auth.AllowKeyRotation {
			if err := a.ensureFreshKey(); err != nil {
				log.Printf("⚠️  Key rotation check failed: %v", err)
			}
		}
		return nil
	}

	// Need to enroll
	if a.config.Server.EnrollToken == "" {
		return fmt.Errorf("no existing identity and no enrollment token provided")
	}

	log.Printf("📝 Enrolling new agent...")
	return a.enroll()
}

func (a *Agent) enroll() error {
	// Generate new keypair
	identity, err := auth.GenerateIdentity()
	if err != nil {
		return err
	}

	// Get Tailscale node ID
	tsPosture, _ := posture.CollectTailscalePosture(a.config.Checks.Tailscale.LocalAPISocket)
	nodeID := tsPosture.NodeID
	if nodeID == "" || nodeID == "unknown" {
		return fmt.Errorf("could not determine Tailscale node ID")
	}

	hostname, _ := os.Hostname()

	enrollReq := auth.EnrollmentRequest{
		Token:        a.config.Server.EnrollToken,
		NodeID:       nodeID,
		Hostname:     hostname,
		PublicKeyB64: identity.PublicKeyB64(),
		OSInfo:       runtime.GOOS + "/" + runtime.GOARCH,
	}

	data, _ := json.Marshal(enrollReq)
	resp, err := a.client.Post(a.config.Server.URL+"/v1/enroll", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enrollment failed: status %d", resp.StatusCode)
	}

	var enrollResp auth.EnrollmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return err
	}

	identity.AgentID = enrollResp.AgentID
	identity.NodeID = nodeID

	// Save identity
	if err := identity.Save(a.keyPath); err != nil {
		return err
	}

	a.identity = identity
	log.Printf("✅ Enrollment successful - Agent ID: %s", identity.AgentID)

	if a.config.Auth.AllowKeyRotation {
		if err := a.ensureFreshKey(); err != nil {
			log.Printf("⚠️  Post-enrollment rotation check failed: %v", err)
		}
	}

	return nil
}

func (a *Agent) reportPosture() {
	// Collect comprehensive posture
	report := a.collectComprehensivePosture()

	// Sign the report
	data, _ := json.Marshal(report)
	signedReq := auth.CreateSignedRequest(a.identity, data)

	// Send signed request
	req, _ := http.NewRequest("POST", a.config.Server.URL+"/v1/report", bytes.NewBuffer(signedReq.Body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vouch-Agent-ID", a.identity.AgentID)
	req.Header.Set("X-Vouch-Signature", signedReq.Signature)
	req.Header.Set("X-Vouch-Timestamp", signedReq.Timestamp.Format(time.RFC3339))
	req.Header.Set("X-Vouch-Nonce", signedReq.Nonce)

	resp, err := a.client.Do(req)
	if err != nil {
		log.Printf("❌ Error sending report: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("❌ Server returned status %d", resp.StatusCode)
		return
	}

	var response struct {
		Status     string   `json:"status"`
		Compliant  bool     `json:"compliant"`
		Violations []string `json:"violations"`
		MinVersion string   `json:"min_version,omitempty"`
	}
	json.NewDecoder(resp.Body).Decode(&response)

	if response.Compliant {
		log.Printf("✅ Posture report accepted - compliant")
	} else {
		log.Printf("⚠️  Non-compliant - violations: %v", response.Violations)
	}

	// Check version
	if response.MinVersion != "" && response.MinVersion > Version {
		log.Printf("⚠️  Agent version %s below minimum %s - update required", Version, response.MinVersion)
	}
}

func (a *Agent) collectComprehensivePosture() map[string]interface{} {
	// Use production-ready CollectorV2
	collector := posture.NewCollectorV2(10 * time.Second)
	ctx := context.Background()

	reportV2 := collector.Collect(ctx)

	// Convert to map for JSON marshaling
	data, _ := json.Marshal(reportV2)
	var report map[string]interface{}
	json.Unmarshal(data, &report)

	// Add agent metadata
	report["agent_version"] = Version

	return report
}

func (a *Agent) ensureFreshKey() error {
	if !a.config.Auth.AllowKeyRotation {
		return nil
	}
	challenge, err := a.requestRotationChallenge()
	if err != nil || challenge == nil {
		return err
	}

	newID, err := auth.GenerateIdentity()
	if err != nil {
		return err
	}

	sig, err := auth.SignChallenge(newID.PrivateKey, challenge.Challenge)
	if err != nil {
		return err
	}

	payload := map[string]string{
		"challenge":  challenge.Challenge,
		"public_key": base64.StdEncoding.EncodeToString(newID.PublicKey),
		"signature":  sig,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	if err := a.submitRotation(body); err != nil {
		return err
	}

	newID.AgentID = a.identity.AgentID
	newID.NodeID = a.identity.NodeID

	if err := a.persistIdentity(newID); err != nil {
		return err
	}

	a.identity = newID
	log.Printf("🔑 Rotated agent key successfully")
	return nil
}

type rotationChallenge struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (a *Agent) requestRotationChallenge() (*rotationChallenge, error) {
	req, err := a.newSignedRequest(http.MethodPost, "/v1/keys/rotate", []byte("{}"))
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var challenge rotationChallenge
		if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
			return nil, err
		}
		if challenge.Challenge == "" {
			return nil, errors.New("rotation challenge missing nonce")
		}
		return &challenge, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("rotation challenge rate limited")
	default:
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("challenge request failed: %d %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
}

func (a *Agent) submitRotation(body []byte) error {
	req, err := a.newSignedRequest(http.MethodPut, "/v1/keys/rotate", body)
	if err != nil {
		return err
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("rotate failed: %d %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	return nil
}

func (a *Agent) newSignedRequest(method, path string, body []byte) (*http.Request, error) {
	payload := body
	if payload == nil {
		payload = []byte("{}")
	}
	signed := auth.CreateSignedRequest(a.identity, payload)
	req, err := http.NewRequest(method, a.endpoint(path), bytes.NewReader(signed.Body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vouch-Agent-ID", a.identity.AgentID)
	req.Header.Set("X-Vouch-Signature", signed.Signature)
	req.Header.Set("X-Vouch-Timestamp", signed.Timestamp.Format(time.RFC3339))
	req.Header.Set("X-Vouch-Nonce", signed.Nonce)
	return req, nil
}

func (a *Agent) persistIdentity(newID *auth.Identity) error {
	backup := a.keyPath + ".bak"
	if _, err := os.Stat(a.keyPath); err == nil {
		if err := os.Rename(a.keyPath, backup); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err := newID.Save(a.keyPath); err != nil {
		if _, restoreErr := os.Stat(backup); restoreErr == nil {
			_ = os.Rename(backup, a.keyPath)
		}
		return err
	}

	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (a *Agent) endpoint(path string) string {
	base := strings.TrimRight(a.config.Server.URL, "/")
	return base + path
}
