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
	r.POST("/v1/enroll", s.handleEnrollment)
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
	var req struct {
		Label            string `json:"label"`
		ExpiresInSeconds int64  `json:"expires_in_seconds"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist token"})
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
	s.tokensMu.Lock()
	defer s.tokensMu.Unlock()

	var tokens []EnrollmentToken
	if err := s.db.Order("created_at desc").Find(&tokens).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list tokens"})
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
	id, err := parseUintParam(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token id"})
		return
	}

	s.tokensMu.Lock()
	defer s.tokensMu.Unlock()

	var token EnrollmentToken
	if err := s.db.First(&token, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "token not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load token"})
		return
	}

	now := time.Now().UTC()
	updates := map[string]interface{}{
		"used_at":     now,
		"redeemed_by": fmt.Sprintf("revoked:%d", now.Unix()),
	}
	if err := s.db.Model(&token).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke token"})
		return
	}

	c.Status(http.StatusNoContent)
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

	if req.Token == "" || req.NodeID == "" || req.PublicKeyB64 == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required fields"})
		return
	}

	pubKey, err := base64.StdEncoding.DecodeString(req.PublicKeyB64)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid public key"})
		return
	}

	s.tokensMu.Lock()
	defer s.tokensMu.Unlock()

	var token EnrollmentToken
	query := s.db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("token_hash = ?", s.tokenHasher.HashString(req.Token))
	if err := query.First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token lookup failed"})
		return
	}
	if token.UsedAt != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token already used"})
		return
	}
	if !token.ExpiresAt.IsZero() && time.Now().After(token.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token expired"})
		return
	}

	if s.enforcer != nil {
		info, err := s.enforcer.GetDeviceInfo(req.NodeID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "tailscale verification failed"})
			return
		}
		if hostname, ok := info["hostname"].(string); ok && hostname != "" && req.Hostname != "" && !strings.EqualFold(hostname, req.Hostname) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "tailscale hostname mismatch"})
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": "device lookup failed"})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist device"})
		return
	}

	now := time.Now().UTC()
	if err := s.db.Model(&token).Updates(map[string]interface{}{
		"used_at":     now,
		"redeemed_by": state.AgentID,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to mark token used"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"agent_id":       state.AgentID,
		"server_version": Version,
		"min_version":    "v0.1.0",
		"policy_etag":    "initial",
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
