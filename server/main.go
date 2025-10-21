package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"expvar"
	"flag"
	"io"
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
	"github.com/haasonsaas/vouch/pkg/telemetry"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

	metricEnrollRequests   = expvar.NewInt("enroll_requests_total")
	metricEnrollFailures   = expvar.NewInt("enroll_failures_total")
	metricReportRequests   = expvar.NewInt("report_requests_total")
	metricReportFailures   = expvar.NewInt("report_failures_total")
	metricRotationRequests = expvar.NewInt("rotation_requests_total")
	metricRotationFailures = expvar.NewInt("rotation_failures_total")
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
	rotationMu       sync.Mutex
	logger           zerolog.Logger
}

func main() {
	flag.Parse()

	configureLogger()
	log.Info().Str("version", Version).Msg("Vouch Server starting")

	ctx := context.Background()
	traceEndpoint := os.Getenv("VOUCH_TRACE_ENDPOINT")
	traceInsecure := false
	if raw := os.Getenv("VOUCH_TRACE_INSECURE"); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			traceInsecure = parsed
		} else {
			log.Warn().Str("value", raw).Msg("Invalid VOUCH_TRACE_INSECURE, defaulting to false")
		}
	}
	sampleRatio := 1.0
	if raw := os.Getenv("VOUCH_TRACE_SAMPLE_RATIO"); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil && parsed > 0 && parsed <= 1 {
			sampleRatio = parsed
		} else {
			log.Warn().Str("value", raw).Msg("Invalid VOUCH_TRACE_SAMPLE_RATIO, defaulting to 1")
		}
	}
	logSpans := false
	if raw := os.Getenv("VOUCH_TRACE_LOG_SPANS"); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			logSpans = parsed
		} else {
			log.Warn().Str("value", raw).Msg("Invalid VOUCH_TRACE_LOG_SPANS, defaulting to false")
		}
	}

	if tp, err := telemetry.SetupTracing(ctx, "vouch-server", Version, traceEndpoint, traceInsecure, sampleRatio, logSpans); err != nil {
		log.Warn().Err(err).Msg("Tracing disabled")
	} else if tp != nil {
		defer func() {
			if err := tp.Shutdown(ctx); err != nil {
				log.Warn().Err(err).Msg("Failed to shutdown tracer provider")
			}
		}()
	}

	// Open database
	db, err := gorm.Open(sqlite.Open(*dbPath), &gorm.Config{})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}

	// Migrate schema
	if err := db.AutoMigrate(&DeviceState{}, &EnrollmentToken{}, &RotationChallenge{}, &AgentNonce{}); err != nil {
		log.Fatal().Err(err).Msg("Failed to migrate database schema")
	}

	// Load policy
	pol := loadPolicy(*policyFile)

	salt := os.Getenv("VOUCH_ENROLL_SALT")
	if *enrollTokenSalt != "" {
		if salt != "" {
			log.Warn().Msg("--enroll-token-salt overrides VOUCH_ENROLL_SALT")
		}
		salt = *enrollTokenSalt
	}
	if salt == "" {
		log.Fatal().Msg("Missing enrollment token salt (set --enroll-token-salt or VOUCH_ENROLL_SALT)")
	}
	saltBytes, err := hex.DecodeString(salt)
	if err != nil {
		log.Fatal().Err(err).Msg("Invalid enrollment token salt")
	}

	enrollAdmin := os.Getenv("VOUCH_ENROLL_ADMIN_TOKEN")
	if *enrollAdminToken != "" {
		if enrollAdmin != "" {
			log.Warn().Msg("--enroll-admin-token overrides VOUCH_ENROLL_ADMIN_TOKEN")
		}
		enrollAdmin = *enrollAdminToken
	}
	if enrollAdmin == "" {
		log.Fatal().Msg("Missing enrollment admin token (set --enroll-admin-token or VOUCH_ENROLL_ADMIN_TOKEN)")
	}

	srv := &Server{
		db:               db,
		policy:           pol,
		tokenHasher:      NewTokenHasher(saltBytes),
		enrollAdminToken: enrollAdmin,
		logger:           log.With().Str("component", "server").Logger(),
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
			log.Fatal().Msg("Enforcement enabled but no Tailscale API key provided")
		}
		srv.enforcer = enforcement.NewTailscaleEnforcer(apiKey, *tailnet, "tag:compliant")
		log.Info().Msg("Tailscale enforcement enabled")
	}

	// Setup HTTP routes
	r := gin.Default()
	r.Use(withRequestContext(srv.logger))
	srv.registerEnrollmentRoutes(r)
	r.POST("/v1/report", srv.rateLimited("report", 120, time.Minute, func(c *gin.Context) string {
		return c.GetHeader("X-Vouch-Agent-ID")
	}, srv.handleReport))
	srv.registerKeyRotationRoutes(r)
	r.GET("/v1/devices", srv.listDevices)
	r.GET("/v1/devices/:hostname", srv.getDevice)
	r.POST("/v1/enforce/:hostname", srv.manualEnforce)
	r.GET("/v1/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy", "version": Version})
	})

	metricsPath := os.Getenv("VOUCH_METRICS_PATH")
	if metricsPath == "" {
		metricsPath = "/debug/metrics"
	}
	r.GET(metricsPath, gin.WrapH(expvar.Handler()))

	log.Info().Str("listen", *listen).Msg("Server listening")
	if err := r.Run(*listen); err != nil {
		log.Fatal().Err(err).Msg("Server run failed")
	}
}

func (s *Server) handleReport(c *gin.Context) {
	metricReportRequests.Add(1)
	logger := requestLogger(c, s.logger)

	report, device, err := s.authenticateReport(c)
	if err != nil {
		metricReportFailures.Add(1)
		switch {
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			respondError(c, http.StatusBadRequest, "failed to read body", s.logger)
		case errors.Is(err, gorm.ErrRecordNotFound):
			respondError(c, http.StatusUnauthorized, "agent not enrolled", s.logger)
		default:
			respondError(c, http.StatusUnauthorized, err.Error(), s.logger)
		}
		return
	}

	eval := policy.Evaluate(&report, s.policy)
	violations, err := json.Marshal(eval.Violations)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to marshal violations")
		respondError(c, http.StatusInternalServerError, "failed to process report", s.logger)
		return
	}
	postureRaw, err := json.Marshal(report)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to marshal posture")
		respondError(c, http.StatusInternalServerError, "failed to process report", s.logger)
		return
	}

	device.Compliant = eval.Compliant
	device.LastSeen = time.Now().UTC()
	device.Violations = string(violations)
	device.PostureRaw = string(postureRaw)

	if err := s.db.Save(device).Error; err != nil {
		metricReportFailures.Add(1)
		logger.Error().Err(err).Str("agent_id", device.AgentID).Msg("Failed to persist device state")
		respondError(c, http.StatusInternalServerError, "failed to persist device", s.logger)
		return
	}

	logger.Info().Str("agent_id", device.AgentID).Bool("compliant", eval.Compliant).Msg("Processed report")

	if s.enforcer != nil && report.NodeID != "unknown" {
		if eval.Compliant {
			if err := s.enforcer.GrantAccess(report.NodeID); err != nil {
				logger.Error().Err(err).Str("hostname", report.Hostname).Msg("Failed to grant enforcement access")
			} else {
				logger.Info().Str("hostname", report.Hostname).Msg("Granted access")
			}
		} else {
			if err := s.enforcer.RevokeAccess(report.NodeID); err != nil {
				logger.Error().Err(err).Str("hostname", report.Hostname).Msg("Failed to revoke enforcement access")
			} else {
				logger.Warn().Str("hostname", report.Hostname).Msg("Revoked access")
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     "ok",
		"compliant":  eval.Compliant,
		"violations": eval.Violations,
		"request_id": requestID(c),
	})
}

func (s *Server) rateLimited(bucket string, limit int, window time.Duration, keyFunc func(*gin.Context) string, next gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := keyFunc(c)
		if key == "" {
			key = c.ClientIP()
		}
		if !s.rateLimiter.Allow(bucket, key, limit, window) {
			c.Header("Retry-After", strconv.Itoa(int(window.Seconds())))
			respondError(c, http.StatusTooManyRequests, "rate limit exceeded", s.logger)
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
		return empty, nil, errors.New("missing authentication headers")
	}

	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return empty, nil, err
	}
	// reset body for downstream readers
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	var report posture.Report
	if err := json.Unmarshal(bodyBytes, &report); err != nil {
		return empty, nil, err
	}

	var device DeviceState
	if err := s.db.Where("agent_id = ?", agentID).First(&device).Error; err != nil {
		return empty, nil, err
	}

	if report.NodeID == "" || !strings.EqualFold(report.NodeID, device.NodeID) {
		return empty, nil, errors.New("node mismatch")
	}

	if len(device.PublicKey) != ed25519.PublicKeySize {
		return empty, nil, errors.New("missing public key")
	}

	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return empty, nil, err
	}

	signed := &auth.SignedRequest{
		Body:      bodyBytes,
		Timestamp: ts,
		Nonce:     nonce,
		Signature: signature,
	}

	if err := auth.VerifySignedRequest(device.PublicKey, signed, 5*time.Minute); err != nil {
		return empty, nil, err
	}

	if err := s.nonceStore.CheckAndStore(agentID, nonce, ts); err != nil {
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
		log.Warn().Str("path", path).Err(err).Msg("Could not load policy file")
		return &policy.Policy{Rules: []policy.Rule{}}
	}

	var pol policy.Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		log.Fatal().Err(err).Msg("Error parsing policy file")
	}

	log.Info().Int("rules", len(pol.Rules)).Msg("Loaded policy rules")
	return &pol
}

func configureLogger() {
	zerolog.TimeFieldFormat = time.RFC3339
	zerolog.DurationFieldUnit = time.Millisecond

	level := zerolog.InfoLevel
	if raw := strings.ToLower(strings.TrimSpace(os.Getenv("VOUCH_LOG_LEVEL"))); raw != "" {
		if parsed, err := zerolog.ParseLevel(raw); err == nil {
			level = parsed
		}
	}

	format := strings.ToLower(strings.TrimSpace(os.Getenv("VOUCH_LOG_FORMAT")))

	var logger zerolog.Logger
	if format == "json" {
		logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	} else {
		writer := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
		logger = zerolog.New(writer).With().Timestamp().Logger()
	}

	logger = logger.Level(level)
	log.Logger = logger
	zerolog.SetGlobalLevel(level)
}
