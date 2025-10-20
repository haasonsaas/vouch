package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/haasonsaas/vouch/pkg/auth"
	"github.com/haasonsaas/vouch/pkg/enforcement"
	"github.com/haasonsaas/vouch/pkg/policy"
	"github.com/haasonsaas/vouch/pkg/posture"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	listen            = flag.String("listen", ":8080", "Listen address")
	policyFile        = flag.String("policy", "policies.yaml", "Policy file path")
	dbPath            = flag.String("db", "vouch.db", "Database path")
	tailscaleAPIKey   = flag.String("tailscale-api-key", "", "Tailscale API key (or set TAILSCALE_API_KEY)")
	tailnet           = flag.String("tailnet", "", "Tailscale tailnet name")
	enableEnforcement = flag.Bool("enforce", false, "Enable Tailscale ACL enforcement")
	enrollTokenSalt   = flag.String("enroll-token-salt", "", "Hex-encoded secret used to hash enrollment tokens (or set VOUCH_ENROLL_SALT)")
	enrollAdminToken  = flag.String("enroll-admin-token", "", "Bearer token required to manage enrollment tokens (or set VOUCH_ENROLL_ADMIN_TOKEN)")
	Version           = "dev"
)

type Server struct {
	db               *gorm.DB
	policy           *policy.Policy
	enforcer         *enforcement.TailscaleEnforcer
	tokenHasher      TokenHasher
	enrollAdminToken string
	tokensMu         sync.Mutex
	deviceMu         sync.Mutex
	nonceStore       *NonceStore
	rateLimiter      *RateLimiter
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
	if err := db.AutoMigrate(&DeviceState{}, &EnrollmentToken{}); err != nil {
		log.Fatalf("Failed to migrate database schema: %v", err)
	}

	// Load policy
	pol := loadPolicy(*policyFile)

	salt := os.Getenv("VOUCH_ENROLL_SALT")
	if *enrollTokenSalt != "" {
		if salt != "" {
			log.Printf("Warning: --enroll-token-salt overrides VOUCH_ENROLL_SALT")
		}
		salt = *enrollTokenSalt
	}
	if salt == "" {
		log.Fatal("Missing enrollment token salt (set --enroll-token-salt or VOUCH_ENROLL_SALT)")
	}
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		log.Fatalf("Invalid enrollment token salt: %v", err)
	}

	enrollAdmin := os.Getenv("VOUCH_ENROLL_ADMIN_TOKEN")
	if *enrollAdminToken != "" {
		if enrollAdmin != "" {
			log.Printf("Warning: --enroll-admin-token overrides VOUCH_ENROLL_ADMIN_TOKEN")
		}
		enrollAdmin = *enrollAdminToken
	}
	if enrollAdmin == "" {
		log.Fatal("Missing enrollment admin token (set --enroll-admin-token or VOUCH_ENROLL_ADMIN_TOKEN)")
	}

	srv := &Server{
		db:               db,
		policy:           pol,
		tokenHasher:      NewTokenHasher(saltBytes),
		enrollAdminToken: enrollAdmin,
	}
	srv.nonceStore = NewNonceStore(db, 5*time.Minute)
	srv.rateLimiter = NewRateLimiter()

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
	srv.registerEnrollmentRoutes(r)
	r.POST("/v1/report", srv.rateLimited("report", 120, time.Minute, func(c *gin.Context) string {
		return c.GetHeader("X-Vouch-Agent-ID")
	}, srv.handleReport))
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
	report, device, err := s.authenticateReport(c)
	if err != nil {
		return
	}

	eval := policy.Evaluate(&report, s.policy)
	violations, _ := json.Marshal(eval.Violations)
	postureRaw, _ := json.Marshal(report)

	device.Compliant = eval.Compliant
	device.LastSeen = time.Now().UTC()
	device.Violations = string(violations)
	device.PostureRaw = string(postureRaw)

	if err := s.db.Save(device).Error; err != nil {
		log.Printf("❌ Failed to persist device state %s: %v", device.AgentID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist device"})
		return
	}

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

func (s *Server) rateLimited(bucket string, limit int, window time.Duration, keyFunc func(*gin.Context) string, next gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := keyFunc(c)
		if key == "" {
			key = c.ClientIP()
		}
		if !s.rateLimiter.Allow(bucket+":"+key, limit, window) {
			c.Header("Retry-After", strconv.Itoa(int(window.Seconds())))
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		next(c)
	}
}

func (s *Server) authenticateReport(c *gin.Context) (posture.Report, *DeviceState, error) {
	var empty posture.Report
	agentID := c.GetHeader("X-Vouch-Agent-ID")
	signature := c.GetHeader("X-Vouch-Signature")
	timestamp := c.GetHeader("X-Vouch-Timestamp")
	nonce := c.GetHeader("X-Vouch-Nonce")

	if agentID == "" || signature == "" || timestamp == "" || nonce == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authentication headers"})
		return empty, nil, errors.New("missing headers")
	}

	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return empty, nil, err
	}
	// reset body for downstream readers
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	var report posture.Report
	if err := json.Unmarshal(bodyBytes, &report); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return empty, nil, err
	}

	var device DeviceState
	if err := s.db.Where("agent_id = ?", agentID).First(&device).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "agent not enrolled"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load device"})
		}
		return empty, nil, err
	}

	if report.NodeID == "" || !strings.EqualFold(report.NodeID, device.NodeID) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "node mismatch"})
		return empty, nil, errors.New("node mismatch")
	}

	if len(device.PublicKey) != ed25519.PublicKeySize {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing public key"})
		return empty, nil, errors.New("missing public key")
	}

	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid timestamp"})
		return empty, nil, err
	}

	signed := &auth.SignedRequest{
		Body:      bodyBytes,
		Timestamp: ts,
		Nonce:     nonce,
		Signature: signature,
	}

	if err := auth.VerifySignedRequest(device.PublicKey, signed, 5*time.Minute); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return empty, nil, err
	}

	if err := s.nonceStore.CheckAndStore(agentID, nonce, ts); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return empty, nil, err
	}

	return report, &device, nil
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
