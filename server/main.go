package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/haasonsaas/vouch/pkg/policy"
	"github.com/haasonsaas/vouch/pkg/posture"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	listen     = flag.String("listen", ":8080", "Listen address")
	policyFile = flag.String("policy", "policies.yaml", "Policy file path")
	dbPath     = flag.String("db", "vouch.db", "Database path")
	Version    = "dev"
)

type DeviceState struct {
	ID         uint      `gorm:"primaryKey"`
	Hostname   string    `gorm:"uniqueIndex"`
	NodeID     string
	Compliant  bool
	LastSeen   time.Time
	Violations string // JSON array
	PostureRaw string `gorm:"type:text"` // JSON
}

type Server struct {
	db     *gorm.DB
	policy *policy.Policy
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
	
	// Setup HTTP routes
	r := gin.Default()
	
	r.POST("/v1/report", srv.handleReport)
	r.GET("/v1/devices", srv.listDevices)
	r.GET("/v1/devices/:hostname", srv.getDevice)
	r.GET("/v1/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
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
	
	// Store device state
	state := DeviceState{
		Hostname:   report.Hostname,
		NodeID:     report.NodeID,
		Compliant:  eval.Compliant,
		LastSeen:   time.Now(),
		Violations: "",
		PostureRaw: "",
	}
	
	s.db.Save(&state)
	
	log.Printf("%s: %s", report.Hostname, eval.String())
	
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"compliant": eval.Compliant,
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
