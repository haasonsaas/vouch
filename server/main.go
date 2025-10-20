package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/haasonsaas/vouch/pkg/enforcement"
	"github.com/haasonsaas/vouch/pkg/policy"
	"github.com/haasonsaas/vouch/pkg/posture"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	listen           = flag.String("listen", ":8080", "Listen address")
	policyFile       = flag.String("policy", "policies.yaml", "Policy file path")
	dbPath           = flag.String("db", "vouch.db", "Database path")
	tailscaleAPIKey  = flag.String("tailscale-api-key", "", "Tailscale API key (or set TAILSCALE_API_KEY)")
	tailnet          = flag.String("tailnet", "", "Tailscale tailnet name")
	enableEnforcement = flag.Bool("enforce", false, "Enable Tailscale ACL enforcement")
	Version          = "dev"
)

type DeviceState struct {
	ID         uint      `gorm:"primaryKey"`
	Hostname   string    `gorm:"uniqueIndex"`
	NodeID     string
	Compliant  bool
	LastSeen   time.Time
	Violations string `gorm:"type:text"` // JSON array
	PostureRaw string `gorm:"type:text"` // JSON
}

type Server struct {
	db       *gorm.DB
	policy   *policy.Policy
	enforcer *enforcement.TailscaleEnforcer
}

func main() {
	flag.Parse()
	
	log.Printf("Vouch Server %s starting...", Version)
	
	// Open database
	db, err := gorm.Open(sqlite.Open(*dbPath), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	
	// Migrate schema
	db.AutoMigrate(&DeviceState{})
	
	// Load policy
	pol := loadPolicy(*policyFile)
	
	srv := &Server{
		db:     db,
		policy: pol,
	}
	
	// Initialize enforcer if enabled
	if *enableEnforcement {
		apiKey := *tailscaleAPIKey
		if apiKey == "" {
			apiKey = os.Getenv("TAILSCALE_API_KEY")
		}
		if apiKey == "" {
			log.Fatal("Enforcement enabled but no Tailscale API key provided")
		}
		srv.enforcer = enforcement.NewTailscaleEnforcer(apiKey, *tailnet, "tag:compliant")
		log.Printf("✅ Tailscale enforcement enabled")
	}
	
	// Setup HTTP routes
	r := gin.Default()
	
	r.POST("/v1/report", srv.handleReport)
	r.GET("/v1/devices", srv.listDevices)
	r.GET("/v1/devices/:hostname", srv.getDevice)
	r.POST("/v1/enforce/:hostname", srv.manualEnforce)
	r.GET("/v1/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy", "version": Version})
	})
	
	log.Printf("Listening on %s", *listen)
	r.Run(*listen)
}

func (s *Server) handleReport(c *gin.Context) {
	var report posture.Report
	if err := c.ShouldBindJSON(&report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Evaluate policy
	eval := policy.Evaluate(&report, s.policy)
	
	// Serialize violations
	violations, _ := json.Marshal(eval.Violations)
	postureRaw, _ := json.Marshal(report)
	
	// Store device state
	state := DeviceState{
		Hostname:   report.Hostname,
		NodeID:     report.NodeID,
		Compliant:  eval.Compliant,
		LastSeen:   time.Now(),
		Violations: string(violations),
		PostureRaw: string(postureRaw),
	}
	
	s.db.Save(&state)
	
	// Enforce via Tailscale if enabled
	if s.enforcer != nil && report.NodeID != "unknown" {
		if eval.Compliant {
			if err := s.enforcer.GrantAccess(report.NodeID); err != nil {
				log.Printf("❌ Failed to grant access to %s: %v", report.Hostname, err)
			} else {
				log.Printf("✅ Granted access to %s", report.Hostname)
			}
		} else {
			if err := s.enforcer.RevokeAccess(report.NodeID); err != nil {
				log.Printf("❌ Failed to revoke access from %s: %v", report.Hostname, err)
			} else {
				log.Printf("🚫 Revoked access from %s", report.Hostname)
			}
		}
	}
	
	log.Printf("%s: %s", report.Hostname, eval.String())
	
	c.JSON(http.StatusOK, gin.H{
		"status":     "ok",
		"compliant":  eval.Compliant,
		"violations": eval.Violations,
	})
}

func (s *Server) listDevices(c *gin.Context) {
	var devices []DeviceState
	s.db.Find(&devices)
	c.JSON(http.StatusOK, devices)
}

func (s *Server) getDevice(c *gin.Context) {
	hostname := c.Param("hostname")
	var device DeviceState
	
	if err := s.db.Where("hostname = ?", hostname).First(&device).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}
	
	c.JSON(http.StatusOK, device)
}

func (s *Server) manualEnforce(c *gin.Context) {
	if s.enforcer == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enforcement not enabled"})
		return
	}
	
	hostname := c.Param("hostname")
	var device DeviceState
	
	if err := s.db.Where("hostname = ?", hostname).First(&device).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "device not found"})
		return
	}
	
	var err error
	if device.Compliant {
		err = s.enforcer.GrantAccess(device.NodeID)
	} else {
		err = s.enforcer.RevokeAccess(device.NodeID)
	}
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"status": "enforced"})
}

func loadPolicy(path string) *policy.Policy {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Warning: Could not load policy file %s: %v", path, err)
		return &policy.Policy{Rules: []policy.Rule{}}
	}
	
	var pol policy.Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		log.Fatalf("Error parsing policy file: %v", err)
	}
	
	log.Printf("Loaded %d policy rules", len(pol.Rules))
	return &pol
}

func (s *Server) handleEnrollment(c *gin.Context) {
	var req struct {
		Token        string `json:"token"`
		NodeID       string `json:"node_id"`
		Hostname     string `json:"hostname"`
		PublicKeyB64 string `json:"public_key"`
		OSInfo       string `json:"os_info"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// For now, accept any token (production would validate against issued tokens)
	if req.Token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	
	// Generate agent ID
	agentID := fmt.Sprintf("agent-%s-%d", req.Hostname, time.Now().Unix())
	
	// Store enrollment (in production, store public key for verification)
	log.Printf("✅ Enrolled new agent: %s (node: %s, host: %s)", agentID, req.NodeID, req.Hostname)
	
	c.JSON(http.StatusOK, gin.H{
		"agent_id":       agentID,
		"server_version": Version,
		"min_version":    "v0.1.0",
		"policy_etag":    "initial",
	})
}
