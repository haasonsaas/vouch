package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Server) registerEnrollmentRoutes(r *gin.Engine) {
	r.POST("/v1/enroll", s.rateLimited("enroll", 30, time.Minute, func(c *gin.Context) string {
		return c.ClientIP()
	}, s.handleEnrollment))
	admin := r.Group("/v1/enroll", s.requireAdmin)
	admin.POST("/tokens", s.handleIssueToken)
	admin.GET("/tokens", s.handleListTokens)
	admin.DELETE("/tokens/:id", s.handleRevokeToken)
}

func (s *Server) requireAdmin(c *gin.Context) {
	authz := c.GetHeader("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
		return
	}
	token := strings.TrimPrefix(authz, "Bearer ")
	if !secureCompare(token, s.enrollAdminToken) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid bearer token"})
		return
	}
	c.Next()
}

func (s *Server) handleIssueToken(c *gin.Context) {
	logger := requestLogger(c, s.logger)
	var req struct {
		Label            string `json:"label"`
		ExpiresInSeconds int64  `json:"expires_in_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, http.StatusBadRequest, err.Error(), logger)
		return
	}

	raw, err := generateEnrollmentSecret()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	expiresAt := time.Time{}
	if req.ExpiresInSeconds > 0 {
		expiresAt = time.Now().Add(time.Duration(req.ExpiresInSeconds) * time.Second)
	}

	record := EnrollmentToken{
		Label:     req.Label,
		TokenHash: s.tokenHasher.HashString(raw),
		ExpiresAt: expiresAt,
	}

	s.tokensMu.Lock()
	defer s.tokensMu.Unlock()

	if err := s.db.Create(&record).Error; err != nil {
		logger.Error().Err(err).Msg("Failed to persist enrollment token")
		respondError(c, http.StatusInternalServerError, "failed to persist token", logger)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":         record.ID,
		"token":      raw,
		"label":      record.Label,
		"expires_at": record.ExpiresAt,
	})
}

func (s *Server) handleListTokens(c *gin.Context) {
	logger := requestLogger(c, s.logger)
	s.tokensMu.Lock()
	defer s.tokensMu.Unlock()

	var tokens []EnrollmentToken
	if err := s.db.Order("created_at desc").Find(&tokens).Error; err != nil {
		logger.Error().Err(err).Msg("Failed to list enrollment tokens")
		respondError(c, http.StatusInternalServerError, "failed to list tokens", logger)
		return
	}

	resp := make([]gin.H, 0, len(tokens))
	for _, t := range tokens {
		resp = append(resp, gin.H{
			"id":          t.ID,
			"label":       t.Label,
			"expires_at":  t.ExpiresAt,
			"used_at":     t.UsedAt,
			"redeemed_by": t.RedeemedBy,
		})
	}

	c.JSON(http.StatusOK, resp)
}

func (s *Server) handleRevokeToken(c *gin.Context) {
	logger := requestLogger(c, s.logger)
	id, err := parseUintParam(c.Param("id"))
	if err != nil {
		respondError(c, http.StatusBadRequest, "invalid token id", logger)
		return
	}

	s.tokensMu.Lock()
	defer s.tokensMu.Unlock()

	var token EnrollmentToken
	if err := s.db.First(&token, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			respondError(c, http.StatusNotFound, "token not found", logger)
			return
		}
		logger.Error().Err(err).Msg("Failed to load enrollment token")
		respondError(c, http.StatusInternalServerError, "failed to load token", logger)
		return
	}

	now := time.Now().UTC()
	updates := map[string]interface{}{
		"used_at":     now,
		"redeemed_by": fmt.Sprintf("revoked:%d", now.Unix()),
	}
	if err := s.db.Model(&token).Updates(updates).Error; err != nil {
		logger.Error().Err(err).Msg("Failed to revoke enrollment token")
		respondError(c, http.StatusInternalServerError, "failed to revoke token", logger)
		return
	}

	c.Status(http.StatusNoContent)
}

func (s *Server) handleEnrollment(c *gin.Context) {
	metricEnrollRequests.Add(1)
	logger := requestLogger(c, s.logger)
	var req struct {
		Token        string `json:"token"`
		NodeID       string `json:"node_id"`
		Hostname     string `json:"hostname"`
		PublicKeyB64 string `json:"public_key"`
		OSInfo       string `json:"os_info"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		metricEnrollFailures.Add(1)
		respondError(c, http.StatusBadRequest, err.Error(), logger)
		return
	}

	if req.Token == "" || req.NodeID == "" || req.PublicKeyB64 == "" {
		metricEnrollFailures.Add(1)
		respondError(c, http.StatusBadRequest, "missing required fields", logger)
		return
	}

	pubKey, err := base64.StdEncoding.DecodeString(req.PublicKeyB64)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		metricEnrollFailures.Add(1)
		respondError(c, http.StatusBadRequest, "invalid public key", logger)
		return
	}

	s.tokensMu.Lock()
	defer s.tokensMu.Unlock()

	var token EnrollmentToken
	query := s.db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("token_hash = ?", s.tokenHasher.HashString(req.Token))
	if err := query.First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			metricEnrollFailures.Add(1)
			respondError(c, http.StatusUnauthorized, "invalid token", logger)
			return
		}
		metricEnrollFailures.Add(1)
		logger.Error().Err(err).Msg("Enrollment token lookup failed")
		respondError(c, http.StatusInternalServerError, "token lookup failed", logger)
		return
	}
	if token.UsedAt != nil {
		metricEnrollFailures.Add(1)
		respondError(c, http.StatusUnauthorized, "token already used", logger)
		return
	}
	if !token.ExpiresAt.IsZero() && time.Now().After(token.ExpiresAt) {
		metricEnrollFailures.Add(1)
		respondError(c, http.StatusUnauthorized, "token expired", logger)
		return
	}

	if s.enforcer != nil {
		info, err := s.enforcer.GetDeviceInfo(req.NodeID)
		if err != nil {
			metricEnrollFailures.Add(1)
			logger.Warn().Err(err).Msg("Tailscale verification failed")
			respondError(c, http.StatusUnauthorized, "tailscale verification failed", logger)
			return
		}
		if hostname, ok := info["hostname"].(string); ok && hostname != "" && req.Hostname != "" && !strings.EqualFold(hostname, req.Hostname) {
			metricEnrollFailures.Add(1)
			respondError(c, http.StatusUnauthorized, "tailscale hostname mismatch", logger)
			return
		}
	}

	s.deviceMu.Lock()
	defer s.deviceMu.Unlock()

	var state DeviceState
	if err := s.db.Where("node_id = ?", req.NodeID).First(&state).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			state = DeviceState{NodeID: req.NodeID}
		} else {
			metricEnrollFailures.Add(1)
			logger.Error().Err(err).Msg("Device lookup failed")
			respondError(c, http.StatusInternalServerError, "device lookup failed", logger)
			return
		}
	}

	if state.AgentID == "" {
		state.AgentID = generateAgentID(req.Hostname)
	}
	state.Hostname = req.Hostname
	state.PublicKey = pubKey
	state.LastSeen = time.Now().UTC()
	state.TagCompliant = false

	if err := s.db.Save(&state).Error; err != nil {
		metricEnrollFailures.Add(1)
		logger.Error().Err(err).Str("node_id", req.NodeID).Msg("Failed persisting device")
		respondError(c, http.StatusInternalServerError, "failed to persist device", logger)
		return
	}

	now := time.Now().UTC()
	if err := s.db.Model(&token).Updates(map[string]interface{}{
		"used_at":     now,
		"redeemed_by": state.AgentID,
	}).Error; err != nil {
		metricEnrollFailures.Add(1)
		logger.Error().Err(err).Str("agent_id", state.AgentID).Msg("Failed marking token used")
		respondError(c, http.StatusInternalServerError, "failed to mark token used", logger)
		return
	}

	logger.Info().Str("agent_id", state.AgentID).Str("node_id", state.NodeID).Msg("Enrollment completed")

	c.JSON(http.StatusOK, gin.H{
		"agent_id":       state.AgentID,
		"server_version": Version,
		"min_version":    "v0.1.0",
		"policy_etag":    "initial",
		"request_id":     requestID(c),
	})
}

func generateEnrollmentSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateAgentID(hostname string) string {
	prefix := strings.ToLower(strings.ReplaceAll(hostname, " ", "-"))
	if prefix == "" {
		prefix = "agent"
	}
	suffix, err := generateEnrollmentSecret()
	if err != nil {
		suffix = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%s", prefix, suffix[:12])
}

func parseUintParam(raw string) (uint, error) {
	if raw == "" {
		return 0, fmt.Errorf("empty")
	}
	id64, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint(id64), nil
}

func secureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
