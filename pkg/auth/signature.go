package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignedRequest represents a signed HTTP request
type SignedRequest struct {
	Body      []byte
	Timestamp time.Time
	Nonce     string
	Signature string
}

// CreateSignedRequest signs a request body
func CreateSignedRequest(identity *Identity, body []byte) *SignedRequest {
	timestamp := time.Now()
	nonce := generateNonce()

	// Message format: timestamp|nonce|body
	message := buildMessage(timestamp, nonce, body)
	signature := identity.Sign(message)

	return &SignedRequest{
		Body:      body,
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
}

// VerifySignedRequest validates a signed request
func VerifySignedRequest(publicKey ed25519.PublicKey, req *SignedRequest, maxAge time.Duration) error {
	// Check timestamp freshness
	age := time.Since(req.Timestamp)
	if age > maxAge {
		return fmt.Errorf("request too old: %v", age)
	}
	if age < -time.Minute {
		return fmt.Errorf("request from future: clock skew detected")
	}

	// Rebuild message
	message := buildMessage(req.Timestamp, req.Nonce, req.Body)

	// Decode and verify signature
	sigBytes, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}

	if !ed25519.Verify(publicKey, message, sigBytes) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func buildMessage(timestamp time.Time, nonce string, body []byte) []byte {
	ts := strconv.FormatInt(timestamp.Unix(), 10)
	parts := []string{ts, nonce, string(body)}
	return []byte(strings.Join(parts, "|"))
}

func generateNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func SignChallenge(priv ed25519.PrivateKey, challenge string) (string, error) {
	if len(priv) == 0 {
		return "", fmt.Errorf("empty private key")
	}
	sig := ed25519.Sign(priv, []byte(challenge))
	return base64.StdEncoding.EncodeToString(sig), nil
}
