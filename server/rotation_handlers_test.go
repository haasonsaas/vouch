package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/haasonsaas/vouch/pkg/auth"
	"github.com/haasonsaas/vouch/pkg/policy"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type rotationTestEnv struct {
	server   *Server
	gin      *gin.Engine
	identity *auth.Identity
}

func newRotationTestEnv(t *testing.T) rotationTestEnv {
	t.Helper()
	dsn := fmt.Sprintf("file:rotation-test-%d?mode=memory&cache=shared", time.Now().UnixNano())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&DeviceState{}, &EnrollmentToken{}, &RotationChallenge{}, &AgentNonce{}))

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	identity := &auth.Identity{
		AgentID:    "agent-123",
		NodeID:     "node-abc",
		PublicKey:  pub,
		PrivateKey: priv,
	}

	srv := &Server{
		db:          db,
		policy:      &policy.Policy{},
		nonceStore:  NewNonceStore(db, time.Minute),
		rateLimiter: NewRateLimiter(),
	}

	device := DeviceState{
		AgentID:   identity.AgentID,
		NodeID:    identity.NodeID,
		PublicKey: identity.PublicKey,
	}
	require.NoError(t, db.Create(&device).Error)

	g := gin.New()
	srv.registerKeyRotationRoutes(g)

	return rotationTestEnv{server: srv, gin: g, identity: identity}
}

func TestIssueRotationChallenge_NoRequirementReturnsNoContent(t *testing.T) {
	env := newRotationTestEnv(t)
	req := signedRequest(t, env, http.MethodPost, "/v1/keys/rotate", []byte("{}"))
	resp := httptest.NewRecorder()
	env.gin.ServeHTTP(resp, req)
	require.Equal(t, http.StatusNoContent, resp.Code)
}

func TestIssueRotationChallenge_ReturnsChallengeWhenRequired(t *testing.T) {
	env := newRotationTestEnv(t)
	require.NoError(t, env.server.db.Model(&DeviceState{}).
		Where("agent_id = ?", "agent-123").
		Update("requires_rotation", true).Error)

	req := signedRequest(t, env, http.MethodPost, "/v1/keys/rotate", []byte("{}"))
	resp := httptest.NewRecorder()
	env.gin.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &payload))
	require.NotEmpty(t, payload["challenge"])
}

func TestCompleteRotation_UpdatesPublicKeyAndClearsRequirement(t *testing.T) {
	env := newRotationTestEnv(t)
	require.NoError(t, env.server.db.Model(&DeviceState{}).
		Where("agent_id = ?", "agent-123").
		Update("requires_rotation", true).Error)

	challengeReq := signedRequest(t, env, http.MethodPost, "/v1/keys/rotate", []byte("{}"))
	challengeResp := httptest.NewRecorder()
	env.gin.ServeHTTP(challengeResp, challengeReq)
	require.Equal(t, http.StatusOK, challengeResp.Code)

	var challenge struct {
		Challenge string    `json:"challenge"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	require.NoError(t, json.Unmarshal(challengeResp.Body.Bytes(), &challenge))

	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sig := ed25519.Sign(newPriv, []byte(challenge.Challenge))

	rotatePayload := map[string]string{
		"challenge":  challenge.Challenge,
		"public_key": base64.StdEncoding.EncodeToString(newPub),
		"signature":  base64.StdEncoding.EncodeToString(sig),
	}
	rotateBody, err := json.Marshal(rotatePayload)
	require.NoError(t, err)
	req := signedRequest(t, env, http.MethodPut, "/v1/keys/rotate", rotateBody)
	resp := httptest.NewRecorder()
	env.gin.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var device DeviceState
	require.NoError(t, env.server.db.First(&device, "agent_id = ?", "agent-123").Error)
	require.False(t, device.RequiresRotation)
	require.Equal(t, []byte(newPub), device.PublicKey)

	var count int64
	require.NoError(t, env.server.db.Model(&RotationChallenge{}).
		Where("agent_id = ?", "agent-123").
		Count(&count).Error)
	require.Zero(t, count)
}

func signedRequest(t *testing.T, env rotationTestEnv, method, path string, body []byte) *http.Request {
	payload := body
	if payload == nil {
		payload = []byte("{}")
	}
	signed := auth.CreateSignedRequest(env.identity, payload)
	req := httptest.NewRequest(method, path, bytes.NewReader(signed.Body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vouch-Agent-ID", env.identity.AgentID)
	req.Header.Set("X-Vouch-Signature", signed.Signature)
	req.Header.Set("X-Vouch-Timestamp", signed.Timestamp.Format(time.RFC3339))
	req.Header.Set("X-Vouch-Nonce", signed.Nonce)
	return req
}
