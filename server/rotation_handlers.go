package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/haasonsaas/vouch/pkg/auth"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const rotationChallengeTTL = 5 * time.Minute

func (s *Server) registerKeyRotationRoutes(r *gin.Engine) {
	agent := r.Group("/v1/keys", s.requireAuthenticatedAgent)
	agent.POST("/rotate", s.rateLimited("rotate-challenge", 20, time.Minute, func(c *gin.Context) string {
		return c.GetHeader("X-Vouch-Agent-ID")
	}, s.issueRotationChallenge))
	agent.PUT("/rotate", s.rateLimited("rotate-complete", 20, time.Minute, func(c *gin.Context) string {
		return c.GetHeader("X-Vouch-Agent-ID")
	}, s.completeRotation))

	admin := r.Group("/v1/keys/admin", s.requireAdmin)
	admin.POST("/agents/:agent_id/rotate", s.markRotationRequired)
	admin.DELETE("/agents/:agent_id/rotate", s.clearRotationRequirement)
}

func (s *Server) requireAuthenticatedAgent(c *gin.Context) {
	agentID := c.GetHeader("X-Vouch-Agent-ID")
	signature := c.GetHeader("X-Vouch-Signature")
	timestamp := c.GetHeader("X-Vouch-Timestamp")
	nonce := c.GetHeader("X-Vouch-Nonce")

	if agentID == "" || signature == "" || timestamp == "" || nonce == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authentication headers"})
		return
	}

	bodyBytes, err := c.GetRawData()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid timestamp"})
		return
	}

	device, err := s.loadDevice(agentID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "agent not enrolled"})
		} else {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to load device"})
		}
		return
	}

	signed := &auth.SignedRequest{
		Body:      bodyBytes,
		Timestamp: ts,
		Nonce:     nonce,
		Signature: signature,
	}

	if err := auth.VerifySignedRequest(device.PublicKey, signed, rotationChallengeTTL); err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if err := s.nonceStore.CheckAndStore(agentID, nonce, signed.Timestamp); err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.Set("device", device)
	c.Set("body", bodyBytes)
	c.Next()
}

func (s *Server) issueRotationChallenge(c *gin.Context) {
	device := c.MustGet("device").(*DeviceState)
	now := time.Now().UTC()
	force := c.Query("force") == "true"

	if !device.RequiresRotation && !force {
		if err := s.db.Where("agent_id = ?", device.AgentID).Delete(&RotationChallenge{}).Error; err != nil {
			log.Printf("❌ Failed clearing stale rotation challenge for %s: %v", device.AgentID, err)
		}
		c.Status(http.StatusNoContent)
		return
	}

	var challenge RotationChallenge
	if err := s.db.Where("agent_id = ?", device.AgentID).First(&challenge).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load challenge"})
			return
		}
	} else if now.Before(challenge.ExpiresAt) {
		c.JSON(http.StatusOK, gin.H{
			"challenge":  challenge.Nonce,
			"expires_at": challenge.ExpiresAt,
		})
		return
	}

	nonce, err := generateRotationNonce()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create challenge"})
		return
	}

	challenge = RotationChallenge{
		AgentID:   device.AgentID,
		Nonce:     nonce,
		IssuedAt:  now,
		ExpiresAt: now.Add(rotationChallengeTTL),
	}

	if err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "agent_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"nonce", "issued_at", "expires_at"}),
	}).Create(&challenge).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist challenge"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"challenge":  challenge.Nonce,
		"expires_at": challenge.ExpiresAt,
	})
}

func (s *Server) completeRotation(c *gin.Context) {
	device := c.MustGet("device").(*DeviceState)

	var req struct {
		Challenge string `json:"challenge"`
		PublicKey string `json:"public_key"`
		Signature string `json:"signature"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Challenge == "" || req.PublicKey == "" || req.Signature == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing fields"})
		return
	}

	var challenge RotationChallenge
	if err := s.db.Where("agent_id = ?", device.AgentID).First(&challenge).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no pending challenge"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load challenge"})
		}
		return
	}

	if time.Now().UTC().After(challenge.ExpiresAt) {
		s.db.Where("agent_id = ?", device.AgentID).Delete(&RotationChallenge{})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "challenge expired"})
		return
	}

	if subtle.ConstantTimeCompare([]byte(challenge.Nonce), []byte(req.Challenge)) != 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "challenge mismatch"})
		return
	}

	newKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(newKeyBytes) != ed25519.PublicKeySize {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid public key"})
		return
	}

	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid signature encoding"})
		return
	}

	if !ed25519.Verify(ed25519.PublicKey(newKeyBytes), []byte(challenge.Nonce), sigBytes) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "challenge signature invalid"})
		return
	}

	s.rotationMu.Lock()
	defer s.rotationMu.Unlock()

	if err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&DeviceState{}).
			Where("agent_id = ?", device.AgentID).
			Updates(map[string]interface{}{
				"public_key":        newKeyBytes,
				"requires_rotation": false,
			}).Error; err != nil {
			return err
		}
		if err := tx.Where("agent_id = ?", device.AgentID).Delete(&RotationChallenge{}).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rotate key"})
		return
	}

	device.PublicKey = append([]byte(nil), newKeyBytes...)
	device.RequiresRotation = false
	log.Printf("🔑 Rotated key for agent %s", device.AgentID)
	c.JSON(http.StatusOK, gin.H{"status": "rotated"})
}

func (s *Server) loadDevice(agentID string) (*DeviceState, error) {
	var device DeviceState
	if err := s.db.Where("agent_id = ?", agentID).First(&device).Error; err != nil {
		return nil, err
	}
	if len(device.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("device missing public key")
	}
	return &device, nil
}

func generateRotationNonce() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Server) markRotationRequired(c *gin.Context) {
	agentID := c.Param("agent_id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing agent id"})
		return
	}

	result := s.db.Model(&DeviceState{}).
		Where("agent_id = ?", agentID).
		Updates(map[string]interface{}{
			"requires_rotation": true,
		})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to flag rotation"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	if err := s.db.Where("agent_id = ?", agentID).Delete(&RotationChallenge{}).Error; err != nil {
		log.Printf("⚠️  Failed clearing prior rotation challenge for %s: %v", agentID, err)
	}

	c.Status(http.StatusNoContent)
}

func (s *Server) clearRotationRequirement(c *gin.Context) {
	agentID := c.Param("agent_id")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing agent id"})
		return
	}

	result := s.db.Model(&DeviceState{}).
		Where("agent_id = ?", agentID).
		Updates(map[string]interface{}{
			"requires_rotation": false,
		})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to clear rotation"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	if err := s.db.Where("agent_id = ?", agentID).Delete(&RotationChallenge{}).Error; err != nil {
		log.Printf("⚠️  Failed clearing rotation challenge for %s: %v", agentID, err)
	}

	c.Status(http.StatusNoContent)
}
