package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"runtime"
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
	identity, err := auth.LoadIdentity(a.config.Auth.KeyPath)
	if err == nil {
		a.identity = identity
		log.Printf("✅ Loaded existing identity")
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
	if err := identity.Save(a.config.Auth.KeyPath); err != nil {
		return err
	}

	a.identity = identity
	log.Printf("✅ Enrollment successful - Agent ID: %s", identity.AgentID)

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
		Status      string   `json:"status"`
		Compliant   bool     `json:"compliant"`
		Violations  []string `json:"violations"`
		MinVersion  string   `json:"min_version,omitempty"`
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
	report := make(map[string]interface{})

	// Basic info
	hostname, _ := os.Hostname()
	report["hostname"] = hostname
	report["agent_version"] = Version
	report["timestamp"] = time.Now()

	// Tailscale
	if a.config.Checks.Tailscale.Enable {
		if ts, err := posture.CollectTailscalePosture(a.config.Checks.Tailscale.LocalAPISocket); err == nil {
			report["tailscale"] = ts
			report["node_id"] = ts.NodeID
		}
	}

	// Firewall
	if a.config.Checks.Firewall.Enable {
		if fw, err := posture.CollectFirewallPosture(a.config.Checks.Firewall.LinuxPrefer); err == nil {
			report["firewall"] = fw
		}
	}

	// Updates
	if a.config.Checks.Updates.Enable {
		if upd, err := posture.CollectUpdatesPosture(); err == nil {
			report["updates"] = upd
		}
	}

	// Secure Boot / TPM
	if a.config.Checks.SecureBoot.Enable {
		if sb, err := posture.CollectSecureBootPosture(); err == nil {
			report["secure_boot"] = sb
		}
	}

	// Legacy basic posture (for backward compat)
	if basic, err := posture.Collect(); err == nil {
		report["os_release"] = basic.OSRelease
		report["kernel"] = basic.Kernel
		report["disk_encrypted"] = basic.DiskEncrypted
		report["services"] = basic.Services
	}

	return report
}
